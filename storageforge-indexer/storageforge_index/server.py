"""HTTP API and graph UI on Flask, with Flask-Login sessions for local accounts. Meant to sit behind a TLS
reverse proxy or on loopback.

GET  /healthz                       liveness + readiness (no auth)
GET  /login                         sign-in page (the only page served without a session)
GET  /                              graph UI; without a valid session, a redirect to /login?next=/
GET  /planner                       storage planner UI; likewise
GET  /manage                        management planner UI: devices, the network language, changes with a rollback; likewise
POST /api/login  {"username", "password"}   start a session (cookie)
POST /api/logout                    end it
POST /api/reauth  {"password"}      confirm the password before commands run on hosts (good for REAUTH_WINDOW)
GET|PUT /api/me                     the signed-in user; PUT {"session_minutes"} sets how long sessions last (30-480)
POST /api/me/password  {"password", "new_password"}   change your own password; every session of yours ends
GET|POST /api/users                  accounts (password confirmed); POST {"username", "password", "role"}
PUT|DELETE /api/users/<name>         {"role"}, {"disabled"}; the last admin stays. Nobody hands out or touches more than they hold
POST /api/users/<name>/reset-link    a single-use link to set a new password (there is no email)
GET|POST /api/invites                single-use sign-up links; POST {"role", "hours"?, "note"?} returns the token once
DELETE /api/invites/<id>             revoke an open link
GET /api/roles                       built-in and custom roles and the permission catalog
POST /api/roles  {"name", "description", "permissions"}   add a custom role
PUT|DELETE /api/roles/<name>         change or remove one; built-in roles stay as they are
GET  /enroll#<token>                 the page an invite or reset link opens (no session)
POST /api/enroll/check  {"token"}    what the link gives (no session)
POST /api/enroll  {"token", "username", "password"}   use the link: make the account, or set its new password (no session)
GET  /search                         the search-only page, where accounts that cannot see hosts land
GET  /api/search/hosts               host names, for filtering a search
PUT  /api/backups/target  {"host", "path"}   after each nightly backup, copy it to that host over its deploy binding
GET  /api/capacity?host=             each mount's usage over 30 days and when it fills up at that rate
GET  /api/file-changes?host=&scan=&limit=   what a scan found changed, grouped by folder (not /api/changes: those are change plans)
GET  /api/dupes?host=&min_size=&limit=   identical files from checksum scans
GET  /api/clamav?host=&closed=           ClamAV on each host and what it found; POST .../detections/<id>/quarantine|restore|ignore
GET  /api/security/posture?host=         What is known about each host's defenses, and what is not. The rest of /api/security is in docs/api-reference.md
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
GET  /api/hostlogs[?host=&unit=&level=&q=&since=&until=&limit=&offset=]   hosts' journal lines, as scans collected them
GET  /api/hostlogs/status[?host=]    how the last pickup from each host went
GET  /api/hostlogs/counts[?host=&since=&until=]   stored lines by level and by UTC hour
GET  /api/hostlogs/units[?host=]     the unit names stored, with a line count each, most first
GET  /api/hostlogs/export?format=csv|json|text[&...]   the same lines as a file
POST /api/scan  {"host": "…"}       queue a vault-backed scan
POST /api/scan/all                  queue a scan of every host with a scan binding
GET  /api/keys                      vault keys (public halves) and host bindings
POST /api/keys  {"name", "type"}     generate a key inside the vault
DELETE /api/keys/<name>              remove a key with no bindings (password confirmed)
DELETE /api/bindings/<id>            remove a binding (password confirmed)
POST /api/hostkey/confirm  {"host", "port", "fingerprint"}   a person compared the host key: pin it, passwords may go there
POST /api/keys/install  {"key", "host", "user", "port", "password", "bind"}
                                    ssh-copy-id the public key, then optionally bind it for scans
GET  /api/access?host=               per host: how scans read the disks, and folders they could not open
GET  /api/access/script?host=&remove=1   the read-only scan access setup (or removal) script, to run as root
POST /api/access/grant  {"host", "password", "admin_user", "remove"}   run that script once over SSH with sudo
GET  /api/folders/duplicates?host=&min_files=&min_size=   folders that are copies by name and structure
GET  /api/filemap?host=&min_size=&folders=&system=   the Graph view: folders holding copies and the lines between them
GET/PUT /api/files/ignore           paths and fragments left out of the file map and of broken-link flags
GET  /api/browse?host=&path=         subfolders of a path with their indexed sizes (for picking move sources)
DELETE /api/hosts/<name>[?keep_design=1]   retire a host (password confirmed; refused while anything is deployed there)
GET|PUT /api/hosts/<name>/schedule   the host's own scan interval and quiet hours ({"interval": "1d", "quiet_hours": "22-6"})
GET  /api/moves                      saved move plans;  POST creates one from {"name", "steps": [...]}
GET|PUT|DELETE /api/moves/<id>       one plan
POST /api/moves/<id>/copy            save a copy of a plan
POST /api/moves/check                check a plan (saved or not) against the index: sizes, space, mounts, loops
GET  /api/moves/<id>/script          the Bash script that runs the plan (copy, verify, cutover, install)
GET  /api/folders/cold?host=&years=&min_size=   folders whose newest file is older than the cutoff
GET  /api/git?host=                  git repositories found by scans, with their copies and archive state
GET|PUT /api/git/ignore              path fragments hidden from the Git tab, for every host ("*") or one; "!x" shows x
GET  /api/shares/check?host=         the NFS/SMB shares in a host's design, checked against the index
GET  /api/shares/script?host=        the script that deploys them on the server and mounts them on clients
POST /api/shares/validate  {"host", "export", "index"|"was"}   check one share before saving it (folder, access, mount points)
POST /api/shares  {"host", "export", "index"|"was"}   add the share to the host's design, or replace share #index or the share "was" {protocol, name, path}
DELETE /api/shares?host=&index= or &protocol=&name=&path=      remove a designed share from the host's design
GET  /api/fs/browse?host=&path=&brief=  folders and files at a path from the index, with mounts, shares and planned mounts; brief=1 only folders and files
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
POST /api/deploy/start               {"kind": jobs|shares|changes|tasks|clamav|security, "ref", "mode": report|apply, "title"?, "report_group"?, "paused"?, "destructive"?}
GET  /api/deploy/groups              recent deploys and how their hosts went
GET  /api/deploy/groups/<id>         one deploy and its runs, with their output (poll while running)
POST /api/deploy/groups/<id>/cancel  {"force"?}: nothing new starts; force also stops what is running
POST /api/deploy/groups/<id>/retry   run it again on the hosts that did not finish (every host, for jobs)
POST /api/deploy/check               {"host"}: what the host can run: a signed probe, or from its last scan if not set up
GET  /api/deploy/runs[/<id>]         deploy history, or one run's output
GET  /api/deploy/jobs/<id>           one deployed job and its run history
POST /api/deploy/jobs/<id>/<verb>    run, dryrun, verify, pause, resume, cutover, log, snapshots, dedupe
POST /api/deploy/jobs/<id>/browse  {"snapshot", "path"}   a folder inside an rsnapshot snapshot (runs ls on the host)
POST /api/deploy/jobs/<id>/restore   {"snapshot", "path"}: copy it back to the source as <path>.restored-<time>
POST /api/deploy/jobs/<id>/retention {"keep": {level: count}}: how many an imported job keeps (a lower count deletes snapshots)
POST /api/deploy/jobs/<id>/forget    stop tracking an imported job; nothing changes on the host
GET  /api/deploy/snapjobs            rsnapshot and snapper jobs found on hosts, imported or not
POST /api/deploy/snapjobs/probe      {"host"}: look again as root (signed, read-only)
POST /api/deploy/snapjobs/import     {"host", "tool", "config"}: track a job found on a host, leaving it as it is
GET  /api/deploy/snapjobs/advice?host=&path=   which tool suits that folder's filesystem
POST /api/deploy/snapjobs/snapper    {"host", "path", "name"}: create a snapper config on btrfs and import it
GET|PUT /api/deploy/settings         report URL and alert channels;  POST /api/deploy/settings/test sends a test alert
GET  /api/remote/nodes               nodes that dial in through the tunnel, and whether each is connected
POST /api/remote/nodes  {"name", "endpoint"}   a new node and its install script (holds its private key; shown once)
POST /api/remote/nodes/<id>/adopt    scan a connected node and prove signed runs work; call again while it says scanning
DELETE /api/remote/nodes/<id>        revoke a node: cuts its tunnel now
POST /api/jobs/report                a job's run result (Authorization: Bearer <job token>; no session)
POST /api/jobs/state                 a running job's latest state event (same token)
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
GET  /api/planner/versions?host=    saved versions of a design, newest first;  GET /api/planner/versions/<id> holds the design
POST /api/planner/versions          {"host", "blueprint", "name"?, "note"?} keep the design on screen as a version
POST /api/planner/versions/compare  {"id", "blueprint"?} a version against the design on screen (or the saved one), in words
POST /api/planner/versions/restore  {"id", "current"?} put a version back, keeping the design it replaces as an automatic version
DELETE /api/planner/versions/<id>   delete a version
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
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit

from flask import Flask, Response, abort, g, jsonify, redirect, request, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import (__version__, access, alerts, inframeasure, netdevice, netscan, errlog, remotes, blueprint, canvas, changes, clamav, deploy, engine, filemap, folders, gitrepos, graph, jobs, logbook, receiving, preflight, protection,
               fromdesign, fsmap, hostconfig, hostkeys, hostlogs, keyinstall, moves, permissions, reinstall, reset, retire, routes_accounts, routes_clamav, routes_git, routes_infra, routes_network, routes_scheduler, routes_secplus, routes_security, scheduler, security, shares, site, snapjobs, tasks, updates, users)
from . import routes_planner
from .runtimes import docker
from .capacity import parse_size, trends
from .db import Database, epoch
from .hostkeys import HostKeyNeeded
from .remote import RemoteError
from .runner import connect_address, scan_via_vault
from .scanner import ScanOptions
from .search import SearchQuery, run_changes, run_dupes, run_search
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
MAX_BLUEPRINT = 2 << 20           # planner designs are the largest body we accept
MAX_IGNORE = 256 << 10            # ignore lists: up to 2000 paths
MAX_REPORT = 512 << 10            # a schedule's run report: the runner keeps its output under this
MAX_JOB_REPORT = 16 << 10         # a job's run line: 2000 characters of message, which JSON escaping can take to 12 KiB
MAX_LONG_TEXT = 512 << 10         # 200,000 characters saved, which JSON escaping can more than double
# Routes that take more than MAX_BODY, and how much. A validator that accepts more than this never gets to see it, so they go together.
BODY_LIMITS = {('PUT', '/api/planner/design'): MAX_BLUEPRINT, ('POST', '/api/planner/changes'): MAX_BLUEPRINT,
               ('POST', '/api/planner/versions'): MAX_BLUEPRINT + MAX_BODY, ('POST', '/api/planner/versions/compare'): MAX_BLUEPRINT + MAX_BODY,
               ('POST', '/api/planner/versions/restore'): MAX_BLUEPRINT + MAX_BODY,       # a design, and the few words that go with it
               ('PUT', '/api/files/ignore'): MAX_IGNORE, ('PUT', '/api/git/ignore'): MAX_IGNORE,
               ('POST', '/api/scheduler/report'): MAX_REPORT, ('POST', '/api/jobs/report'): MAX_JOB_REPORT,
               ('POST', '/api/security/report'): MAX_REPORT,       # a sentinel's path can be 4 KiB, which base64 makes 5.5
               ('POST', '/api/dsl/compile'): MAX_LONG_TEXT, ('POST', '/api/dsl/whatif'): MAX_LONG_TEXT, ('POST', '/api/dsl/stage'): MAX_LONG_TEXT,
               ('POST', '/api/map/views'): MAX_LONG_TEXT, ('POST', '/api/map/designs'): MAX_LONG_TEXT,
               ('POST', '/api/security/behavior/yara/rules'): MAX_LONG_TEXT, ('POST', '/api/security/behavior/falco'): MAX_LONG_TEXT}
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


QUIET_RE = re.compile(r'(\d{1,2})-(\d{1,2})')


def in_quiet_hours(quiet: str | None, hour: int) -> bool:
    """quiet is "22-6": from 22:00 up to, not including, 06:00, across midnight if it needs to."""
    m = QUIET_RE.fullmatch(quiet or '')
    if not m:
        return False
    start, end = int(m[1]), int(m[2])
    return start <= hour < end if start <= end else hour >= start or hour < end


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
        self.scan_done = threading.Event()
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
        threading.Thread(target=self._schedule, args=(scan_interval,), name='scheduler', daemon=True).start()
        threading.Thread(target=self._nightly, name='nightly', daemon=True).start()
        self.alerts_wake = threading.Event()
        threading.Thread(target=self._alerts, name='alerts', daemon=True).start()
        threading.Thread(target=self._security, name='security', daemon=True).start()

    def _alerts(self):
        time.sleep(30)
        while True:
            try:
                alerts.evaluate(self.db)
            except Exception:
                errlog.trace()
            self.alerts_wake.wait(ALERT_TICK)
            self.alerts_wake.clear()

    def _security(self):
        """Timelocks that have waited long enough, and hosts due for a reading. Each run on a host can take a while, so not on the alerts thread."""
        time.sleep(60)
        while True:
            try:
                done = security.tick(self.db)
                done['infra'] = inframeasure.tick(self.db)
                done['devices'] = netdevice.tick(self.db)
                done['netscan'] = netscan.tick(self.db)
                if any(done.values()):
                    self.alerts_wake.set()
            except Exception:
                errlog.trace()
            time.sleep(60)

    @staticmethod
    def canonical(conn, host: str) -> str:
        """One name per machine: a binding's IP, an ssh alias and the hostname all queue as the indexed hostname, so
        the scheduler and "Scan now" can't start two scans of one host under different names. A host just rekeyed has no
        scanned address, so its name reaches nothing yet: the IP stays as given, which is what its key binding names."""
        row = conn.all("""SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h) OR ssh_host = :h OR (ip_address = :h AND ssh_host IS NOT NULL)
                          ORDER BY CASE WHEN lower(hostname) = lower(:h) THEN 0 WHEN ssh_host = :h THEN 1 ELSE 2 END,
                                   last_scanned_at DESC""", {'h': host})   # a host's self-reported IP comes last
        return row[0][0] if row else host

    def enqueue(self, host: str, actor: str) -> int:
        conn = self.db.connect()
        try:
            host = self.canonical(conn, host)
            with self.enqueue_lock:     # workers run side by side: two requests at once must not start one host twice
                # a first scan was queued by address and gives the host its name while it runs
                busy = conn.scalar("""SELECT job_id FROM scan_jobs WHERE status IN ('queued', 'running')
                                      AND (host = :h OR host IN (SELECT ssh_host FROM hosts WHERE hostname = :h))""", {'h': host})
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
                                         log=lambda m: errlog.say(f'[job {jid}] {m}'))
                    status, result = res['status'], res
                except Exception as exc:
                    status, result = 'failed', {'error': str(exc)}
                conn.execute('UPDATE scan_jobs SET status = :s, finished_at = :t, result_json = :r WHERE job_id = :j',
                             {'s': status, 't': int(time.time()), 'r': json.dumps(result, default=str), 'j': jid})
                self.scan_db.prune(conn)             # cheap deletes; keeps change history and denied lists bounded
            except Exception:
                errlog.trace()
            finally:
                conn.close()
                self.scan_done.set()

    def bound_hosts(self) -> list[str]:
        """Hosts bound by name for scanning, under their indexed hostnames."""
        return self.due_hosts(0, schedules=False)

    def due_hosts(self, interval: int | None, now: float | None = None, schedules: bool = True) -> list[str]:
        """Bound hosts whose last scan job (of any outcome) is older than the interval: the host's own if it has one, else
        the given one (None: only hosts with their own). A restart therefore never triggers a burst of scans, and a host
        that keeps failing is retried once per interval, not every tick. Quiet hours hold back the scan, not the clock."""
        now = now or time.time()
        conn = self.db.connect()
        try:
            due = []
            devices = {x for row in conn.all('SELECT name, address FROM network_devices') for x in row}       # bound for reading, and read in their own way
            for (pattern,) in conn.all("""SELECT DISTINCT host_pattern FROM key_bindings
                                          WHERE pattern_kind = 'host' AND allowed_actions LIKE :a""", {'a': '%scan%'}):
                name = self.canonical(conn, pattern)
                if pattern in devices or name in devices:
                    continue
                last = conn.scalar('SELECT max(queued_at) FROM scan_jobs WHERE host IN (:n, :p)', {'n': name, 'p': pattern})
                done = epoch(conn.scalar('SELECT last_scanned_at FROM hosts WHERE hostname = :n', {'n': name}))
                last = max(x for x in (last, done, 0) if x is not None) or None     # CLI scans count too
                every, quiet = interval, None
                if schedules:
                    own = conn.all('SELECT scan_interval, quiet_hours FROM hosts WHERE hostname = :n', {'n': name})
                    every, quiet = (own[0][0] or interval, own[0][1]) if own else (interval, None)
                if every is None or in_quiet_hours(quiet, time.localtime(now).tm_hour):
                    continue
                if name not in due and (last is None or now - last >= every * 0.95):
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
                out['copy'] = self.copy_off(conn, out['backup']['path'], 'system')
            except (Exception, SystemExit) as exc:
                out['error'] = str(exc)
                self.audit(conn, 'system', 'backup.create', 'failed', None, {'error': str(exc)[:300]})
            if CONFIG_EXPORT_DIR:
                try:
                    out['hostconfigs'] = hostconfig.export_to(conn, site.export_dir(conn, CONFIG_EXPORT_DIR))
                    self.audit(conn, 'system', 'hostconfig.export', 'ok', None, out['hostconfigs'])
                except Exception as exc:
                    out['hostconfigs_error'] = str(exc)
                    self.audit(conn, 'system', 'hostconfig.export', 'failed', None, {'error': str(exc)[:300]})
            out['pruned'] = self.db.prune(conn)
        finally:
            conn.close()
        errlog.say(f'nightly: {out}')
        return out

    def copy_off(self, conn, path: str, actor: str) -> str | None:
        """Copy a backup to the host in the backup.target setting, if there is one. Returns the error, if any."""
        from . import backup
        target = alerts.get_setting(conn, 'backup.target')
        if not target:
            return None
        try:
            backup.copy_off(self.scan_db, conn, path, target, BACKUP_KEEP)
        except Exception as exc:
            self.audit(conn, actor, 'backup.copy', 'failed', target['host'], {'error': str(exc)[:300]})
            return str(exc)
        self.audit(conn, actor, 'backup.copy', 'ok', target['host'], {'path': target['path']})
        return None

    def _nightly(self):
        from . import backup
        time.sleep(120)                          # let start-up and any first scan settle
        try:
            newest = backup.listing()
            if self.db.dialect == 'sqlite' and (not [b for b in newest if b['kind'] == 'essentials']
                                                or time.time() - newest[0]['created'] > 86400):
                self.nightly_once()
        except Exception:
            errlog.trace()
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
                errlog.trace()

    def _schedule(self, interval: int | None):
        while True:
            try:
                for h in self.due_hosts(interval):
                    self.enqueue(h, 'scheduler')
            except Exception:
                errlog.trace()
            time.sleep(min(interval or SCHEDULE_TICK, SCHEDULE_TICK))


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


def remember(cache: dict, key: tuple, result, latest, keep: int = 8):
    """Into a cache keyed by (..., scan id): what an older scan left goes, then the oldest entries beyond keep. The Cleanup
    tab asks for cold and duplicate folders at once: both stay."""
    for k in [k for k in cache if k[-1] != latest]:
        del cache[k]
    while len(cache) >= keep:
        del cache[next(iter(cache))]
    cache[key] = result


def session_cookie_name(secure: bool) -> str:
    """Browsers keep cookies by host, not port: sites on one machine need their own name, or signing in to one signs
    you out of the other."""
    suffix = os.environ.get('STORAGEFORGE_COOKIE_SUFFIX', '')
    if suffix and not re.fullmatch(r'[a-z0-9-]{1,32}', suffix):
        raise SystemExit('STORAGEFORGE_COOKIE_SUFFIX: lowercase letters, digits and - only (max 32)')
    return f'{"__Host-" if secure else ""}sf_session{"_" + suffix if suffix else ""}'


def create_app(core: App, session_secret: str, secure_cookies: bool = False, proxy_hops: int = 0,
               proxy_host: str = '') -> Flask:
    web = Flask(__name__, static_folder=None)
    if proxy_hops:   # trust X-Forwarded-For from this many proxies, so limits and audit see the real client
        web.wsgi_app = _FromProxy(web.wsgi_app, proxy_hops, proxy_host)
    web.config.update(
        SECRET_KEY=session_secret, MAX_CONTENT_LENGTH=MAX_BODY,
        # __Host-: browsers only accept it over https, for Path=/ and without Domain, so no other site or subdomain can set it
        SESSION_COOKIE_NAME=session_cookie_name(secure_cookies),
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

    def same_host_and_port(origin: str, host: str) -> bool:
        """Plain HTTP gets no Sec-Fetch-Site, so this is all that tells a page on another port apart. A Host without a port
        says nothing about it: a proxy may have dropped it."""
        try:
            o, h = urlsplit(origin), urlsplit(f'//{host}')
            port = o.port or {'http': 80, 'https': 443}.get(o.scheme)
            return o.hostname == h.hostname and (h.port is None or port == h.port)
        except ValueError:
            return False

    @web.before_request
    def same_origin_only():
        """SameSite counts another port on this host as the same site, so a page there could still post a form here with
        the cookie. Job reports send no such headers, and browsers that send neither are too old to reach this CSP."""
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return None
        fetch, origin = request.headers.get('Sec-Fetch-Site'), request.headers.get('Origin')
        if fetch:
            ok = fetch in ('same-origin', 'none')
        else:
            ok = not origin or same_host_and_port(origin, request.host)
        return None if ok else (jsonify(error='this request came from another site'), 403)

    @web.before_request
    def role_allows():
        """Default-deny: see permissions.required."""
        if current_user.is_authenticated and not permissions.allows(current_user.permissions, request.method, request.path):
            return jsonify(error=f'your account ({current_user.role}) may not do this'), 403
        return None

    def need(permission: str):
        """For what a route's path cannot say, such as a deploy's mode."""
        if permission not in current_user.permissions:
            abort(403, description=f'your account ({current_user.role}) may not do this')

    def may_hand_out(role: str):
        """Nobody gives out, or changes the account of, a role that can do more than they can."""
        if not users.permissions_of(conn(), role) <= current_user.permissions:
            abort(403, description=f'the role {role} can do things your account cannot')

    @web.before_request
    def body_limit():
        limit = BODY_LIMITS.get((request.method, request.path))
        if request.method == 'POST' and re.fullmatch(r'/api/devices/[^/]+/report', request.path):     # a route with a name in it, as long as the others in the language
            limit = MAX_LONG_TEXT
        if limit:
            request.max_content_length = limit

    @web.after_request
    def headers(resp: Response):
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        resp.headers['Server'] = 'StorageForge'
        if ACCESS_LOG == 'all' or (ACCESS_LOG == 'changes' and (request.method not in ('GET', 'HEAD') or resp.status_code >= 500
                                                                  or resp.status_code == 429)):
            errlog.say(f'{request.remote_addr} {request.method} {request.path} {resp.status_code}')
        return resp

    @web.errorhandler(Exception)
    def on_error(exc):
        if isinstance(exc, HTTPException):
            return jsonify(error=exc.description), exc.code
        if isinstance(exc, HostKeyNeeded):   # the UI shows the fingerprint, then POSTs /api/hostkey/confirm and retries
            return jsonify(error=str(exc), hostkey=exc.as_dict()), 409
        if isinstance(exc, (ValueError, VaultError)):
            return jsonify(error=str(exc)), 400
        if isinstance(exc, LookupError) and not isinstance(exc, (KeyError, IndexError)):     # "no such deploy", from a route with no handler of its own
            return jsonify(error=str(exc)), 404
        errlog.trace()
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
        return app_page('index.html')

    @web.get('/planner')
    def planner():
        return app_page('planner.html')

    @web.get('/manage')
    def manage_page():
        return app_page('manage.html')

    def app_page(name):
        if not current_user.is_authenticated:
            return to_login()
        return page(name) if 'hosts.view' in current_user.permissions else redirect('/search')

    @web.get('/search')
    def search_page():
        return page('search.html') if current_user.is_authenticated else to_login()

    @web.get('/enroll')
    def enroll_page():
        return page('enroll.html')

    @web.get('/login')
    def login_page():
        if current_user.is_authenticated:
            return redirect(safe_next(request.args.get('next')))
        return page('login.html')

    @web.get('/<any("login.js", "enroll.js", "style.css", "tokens.css", "components.css", "favicon.svg"):name>')
    def public_static(name):
        resp = send_from_directory(STATIC, name, max_age=0)
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    @web.get('/<any("session.js", "kernel.js", "chrome.js", "router.js", "search.js", "app.js", "topology.js", "checks.js", "moves.js", "changes.js", "filemap.js", "gitview.js", "rebuildview.js", "dockerview.js", "infraview.js", "mapview.js", "netscanview.js", "manage.js", "manage.css", "securitymore.js", "deployview.js", "fsbrowse.js", "sharewiz.js", "tasks.js", "scheduler.js", "planner.js", "planner.css", "securityview.js", "hostlogsview.js"):name>')
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
        if len(signed_in_from) >= 10_000:       # forgetting only drops an exemption from the daily limit
            signed_in_from.clear()
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
        return dict(site=site.name(conn()), username=current_user.username, role=current_user.role, permissions=sorted(current_user.permissions), session_minutes=current_user.session_minutes,
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

    @web.post('/api/me/password')
    @login_required
    @limiter.limit(LOGIN_LIMIT_PER_USER, key_func=lambda: f'password:{current_user.get_id()}')
    def api_me_password():
        body = json_body()
        ok = users.confirm(conn(), current_user.user_id, str(body.get('password') or ''))
        core.audit(conn(), actor(), 'web.password', 'ok' if ok else 'denied', None, {})
        if not ok:
            return jsonify(error='that is not your current password'), 403
        users.set_password(conn(), current_user.username, str(body.get('new_password') or ''))
        users.end_all_sessions(conn(), current_user.username)
        return jsonify(signed_out=True)

    ctx = SimpleNamespace(login_limit=LOGIN_LIMIT_PER_IP, core=core, db=db, limiter=limiter, conn=conn, actor=actor, need=need, may_hand_out=may_hand_out, json_body=json_body,
                          arg_num=arg_num, password_stale=password_stale, password_confirmed=password_confirmed,
                          need_for_commands=lambda c, kind, ref: need_for_commands(c, kind, ref))
    routes_accounts.register(web, ctx)

    # data
    @web.get('/api/hosts')
    @login_required
    def api_hosts():
        rows = conn().all('SELECT hostname, ip_address, os_info, last_scanned_at FROM hosts ORDER BY hostname')
        graph_hosts = [r[0] for r in conn().all("SELECT label FROM graph_nodes WHERE kind = 'Host' AND host IS NOT NULL ORDER BY label")]
        return jsonify(indexed=[dict(zip(('hostname', 'ip', 'os', 'last_scanned_at'), (*r[:3], epoch(r[3]))))
                                for r in rows],
                       graph=graph_hosts)

    @web.delete('/api/hosts/<name>')
    @login_required
    @password_confirmed
    def api_host_retire(name):
        host = core.canonical(conn(), name)
        try:
            gone = retire.retire(conn(), host, bool(request.args.get('keep_design')))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except ValueError as exc:
            return jsonify(error=str(exc)), 409
        core.audit(conn(), actor(), 'hosts.retire', 'ok', host, gone)
        core.alerts_wake.set()
        return jsonify(host=host, removed=gone)

    @web.route('/api/hosts/<name>/schedule', methods=['GET', 'PUT'])
    @login_required
    def api_host_schedule(name):
        host = core.canonical(conn(), name)
        if not conn().scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': host}):
            return jsonify(error=f'{name} has not been scanned'), 404
        if request.method == 'PUT':
            from .cli import parse_age
            body = json_body()
            quiet = str(body.get('quiet_hours') or '').strip() or None
            m = QUIET_RE.fullmatch(quiet or '')
            if quiet and not (m and int(m[1]) < 24 and int(m[2]) < 24 and m[1] != m[2]):
                raise ValueError('quiet hours look like 22-6: from 22:00 up to 06:00')
            try:
                every = parse_age(str(body['interval'])) if body.get('interval') else None
            except Exception:
                raise ValueError('give the interval like 90m, 6h or 1d') from None
            conn().execute('UPDATE hosts SET scan_interval = :i, quiet_hours = :q WHERE hostname = :h', {'i': every, 'q': quiet, 'h': host})
            core.audit(conn(), actor(), 'hosts.schedule', 'ok', host, {'interval': every, 'quiet_hours': quiet})
        every, quiet = conn().all('SELECT scan_interval, quiet_hours FROM hosts WHERE hostname = :h', {'h': host})[0]
        return jsonify(host=host, interval=every, quiet_hours=quiet)

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
        return Response(canvas.dumps(graph.load(conn(), host), canvas.extras(conn(), host)), mimetype='application/json',
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

    @web.get('/api/search/hosts')
    @login_required
    def api_search_hosts():
        return jsonify(hosts=[r[0] for r in conn().all('SELECT hostname FROM hosts ORDER BY hostname')])

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

    def hostlog_filter():
        a = request.args
        return hostlogs.clean_filter(a.get('host'), a.get('unit'), a.get('level'), a.get('q'), a.get('since'), a.get('until'))

    @web.get('/api/hostlogs')
    @login_required
    def api_hostlogs():
        return jsonify(hostlogs.page(conn(), hostlog_filter(), arg_num('limit', 100, 1, 500), arg_num('offset', 0, 0, hostlogs.MAX_EXPORT)))

    @web.get('/api/hostlogs/status')
    @login_required
    def api_hostlogs_status():
        return jsonify(hosts=hostlogs.status(conn(), request.args.get('host') or None))

    @web.get('/api/hostlogs/counts')
    @login_required
    def api_hostlogs_counts():
        a = request.args
        return jsonify(hostlogs.counts(conn(), hostlogs.range_filter(a.get('host'), a.get('since'), a.get('until'))))

    @web.get('/api/hostlogs/units')
    @login_required
    def api_hostlogs_units():
        host = hostlogs.range_filter(request.args.get('host'))['host']
        return jsonify(host=host, units=hostlogs.units(conn(), host))

    @web.get('/api/hostlogs/export')
    @login_required
    def api_hostlogs_export():
        f, fmt = hostlog_filter(), request.args.get('format') or 'csv'
        text, n = hostlogs.export(conn(), f, fmt)
        core.audit(conn(), actor(), 'hostlogs.export', 'ok', f['host'], {'format': fmt, 'lines': n, 'q': f['q'], 'unit': f['unit'], 'level': f['level']})
        mime, ext = hostlogs.FORMATS[fmt]
        stamp = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
        return Response(text, mimetype=mime.split(';')[0], headers={
            'Content-Disposition': f'attachment; filename="storageforge-hostlogs-{stamp}.{ext}"', 'X-Content-Type-Options': 'nosniff'})

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

    @web.delete('/api/keys/<name>')
    @login_required
    @password_confirmed
    def api_key_remove(name):
        v = Vault(db, conn())
        key = next((k for k in v.list_keys() if k['name'] == name), None)
        if not key:
            return jsonify(error=f'no key named {name!r}'), 404
        if key['bindings']:
            return jsonify(error=f'{name} still has {key["bindings"]} binding(s): remove them first'), 409
        v.remove_key(name)
        core.audit(conn(), actor(), 'vault.key.remove', 'ok', None, {'name': name, 'fingerprint': key['fingerprint']})
        return jsonify(removed=name)

    @web.delete('/api/bindings/<int:binding_id>')
    @login_required
    @password_confirmed
    def api_binding_remove(binding_id):
        v = Vault(db, conn())
        b = next((x for x in v.bindings() if x['binding_id'] == binding_id), None)
        if not b:
            return jsonify(error=f'no binding #{binding_id}'), 404
        v.unbind(binding_id)
        core.audit(conn(), actor(), 'vault.unbind', 'ok', b['pattern'], {'key': b['key'], 'user': b['user']})
        return jsonify(removed=binding_id)

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
        core.audit(conn(), actor(), action, 'ok', host, {'user': res['user'], 'via': res['via'], 'passwordless': res.get('passwordless')})
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
        body = json_body()
        if moves.has_raw_hooks(moves.normalize(body)):
            need('hosts.command')
        pid = moves.save_plan(conn(), body, actor())
        core.audit(conn(), actor(), 'moves.save', 'ok', None, {'plan': pid})
        return jsonify(moves.get_plan(conn(), pid)), 201

    @web.route('/api/moves/<int:plan_id>', methods=['GET', 'PUT', 'DELETE'])
    @login_required
    def api_move(plan_id):
        try:
            if request.method == 'PUT':
                body = json_body()
                if moves.has_raw_hooks(moves.normalize(body)) or moves.has_raw_hooks(moves.get_plan(conn(), plan_id)):
                    need('hosts.command')
                moves.save_plan(conn(), body, actor(), plan_id)
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

    @web.post('/api/moves/<int:plan_id>/copy')
    @login_required
    def api_move_copy(plan_id):
        try:
            if moves.has_raw_hooks(moves.get_plan(conn(), plan_id)):
                need('hosts.command')
            pid = moves.copy_plan(conn(), plan_id, actor())
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        core.audit(conn(), actor(), 'moves.save', 'ok', None, {'plan': pid, 'copied_from': plan_id})
        return jsonify(moves.get_plan(conn(), pid)), 201

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

    @web.get('/api/capacity')
    @login_required
    def api_capacity():
        return jsonify(mounts=trends(conn(), request.args.get('host') or None))

    @web.get('/api/file-changes')
    @login_required
    def api_file_changes():
        host = request.args.get('host', '').strip()
        if not host:
            raise ValueError('give host')
        scan = request.args.get('scan')
        limit = arg_num('limit', 20000, 1, 200000, int)
        info, rows = run_changes(conn(), host, int(scan) if scan else None, limit)
        folders: dict[str, dict] = {}
        for r in rows:       # a 50,000-file npm install is one line, not a page
            parts = r['path'].lstrip('/').split('/')
            top = '/' + '/'.join(parts[:3 if len(parts) > 3 else max(1, len(parts) - 1)])
            f = folders.setdefault(top, {'folder': top, 'added': 0, 'modified': 0, 'deleted': 0, 'delta': 0})
            f[r['change']] += 1
            f['delta'] += (r['new_size'] or 0) - (r['old_size'] or 0)
        return jsonify(scan=info, folders=sorted(folders.values(), key=lambda f: -(f['added'] + f['modified'] + f['deleted']))[:500], truncated=len(rows) >= limit)

    @web.get('/api/dupes')
    @login_required
    def api_dupes():
        return jsonify(groups=run_dupes(conn(), request.args.get('host') or None, parse_size(request.args.get('min_size') or '1MiB'), arg_num('limit', 50, 1, 500, int)))

    @web.get('/api/git')
    @login_required
    def api_git():
        return jsonify(gitrepos.listing(conn(), request.args.get('host') or None, bool(request.args.get('all'))))

    @web.route('/api/git/ignore', methods=['GET', 'PUT'])
    @login_required
    def api_git_ignore():
        if request.method == 'PUT':
            body = json_body()
            paths = body.get('paths')
            if not isinstance(paths, list) or not all(isinstance(x, str) for x in paths):
                return jsonify(error='paths must be a list of path fragments'), 400
            gitrepos.save_ignore(conn(), str(body.get('host') or ''), paths, actor())
            core.audit(conn(), actor(), 'git.ignore', 'ok', str(body.get('host') or '') or None, {'paths': len(paths)})
        return jsonify(ignore=gitrepos.ignore_lists(conn()), builtin=list(gitrepos.NOISE))

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

    routes_git.register(web, ctx)
    routes_clamav.register(web, ctx)
    routes_secplus.register(web, ctx)      # first: it gives the others ctx.step_up
    routes_security.register(web, ctx)
    routes_infra.register(web, ctx)
    routes_network.register(web, ctx)
    routes_planner.register(web, ctx)

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
            host, path = request.args.get('host', ''), request.args.get('path') or '/'
            index = kept_dir_index() if request.args.get('brief') else None    # still being built or a scan is running: read the tables
            return jsonify(fsmap.listing(conn(), host, path, index) if index is not None else fsmap.browse(conn(), host, path))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.route('/api/tasks', methods=['GET', 'POST'])
    @login_required
    def api_tasks():
        c = conn()
        if request.method == 'POST':
            body = json_body()
            if tasks.has_command(tasks.normalize(body)):
                need('hosts.command')
            tid = tasks.save_task(c, body, actor())
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
                body = json_body()
                if tasks.has_command(tasks.normalize(body)) or tasks.has_command(tasks.get_task(c, task_id)):
                    need('hosts.command')
                tasks.save_task(c, body, actor(), task_id)
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
                       alerts=alerts.list_alerts(c), drift=alerts.drift(c),
                       settings=alerts.settings(c) if 'settings.manage' in current_user.permissions else alerts.public_settings(c),
                       runs=deploy.history(c, limit=30), plans=moves.list_plans(c), updates=updates.overview(c),
                       share_hosts=shares.designed_hosts(c))

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
        if kind == 'schedules':
            try:
                sched = scheduler.get_schedule(c, int(ref))
            except LookupError:            # a deleted schedule: all that is left to do is take it off its hosts
                if not options.get('remove'):
                    raise ValueError(f'schedule {ref} no longer exists') from None
                return scheduler.orphan_items(db, c, int(ref), mode, actor())
            report_url = alerts.get_setting(c, 'report_url')
            return scheduler.deploy_items(db, c, sched, mode, report_url, actor(),
                                          bool(options.get('run')), bool(options.get('remove')))
        if kind == updates.KIND:
            return updates.deploy_items(c, str(ref or updates.ALL), mode)
        if kind == 'clamav':
            return clamav.deploy_items(db, c, str(ref or ''), mode, actor(), bool(options.get('run')), bool(options.get('remove')))
        if kind == 'security':
            return security.deploy_items(db, c, str(ref or ''), mode, actor(), bool(options.get('remove')), bool(options.get('rearm')))
        raise ValueError('kind is jobs, shares, changes, tasks, schedules, updates, clamav or security')

    def need_for_commands(c, kind, ref):
        """Raw commands run as root, so deploying them takes hosts.command, whoever wrote them. Taking them off a host doesn't."""
        try:
            holds = (moves.has_raw_hooks(moves.get_plan(c, int(ref))) if kind == 'jobs' else
                     tasks.has_command(tasks.get_task(c, int(ref))) if kind == 'tasks' else
                     scheduler.holds_commands(c, scheduler.get_schedule(c, int(ref))) if kind == 'schedules' else False)
        except LookupError:
            return
        if holds:
            need('hosts.command')

    def second_hops(c, kind, ref):
        """Hosts this deploy's rsync blocks log in to by themselves, with the first host's own key. No signature reaches them and no run
        is recorded there, so the audit row is what says they were involved."""
        try:
            if kind == 'tasks':
                return tasks.second_hops(tasks.get_task(c, int(ref)))
            if kind == 'schedules':
                return scheduler.second_hops(c, scheduler.get_schedule(c, int(ref)))
        except (LookupError, TypeError, ValueError):
            pass
        return []

    def send_receivers(c, kind, ref):
        """Hosts this deploy's sends reach. Each gets a signed run of its own, and the audit row of the deploy says which."""
        try:
            if kind == 'changes':
                return changes.receivers(c, changes.get_plan(c, int(ref)))
            if kind == 'tasks':
                return tasks.receivers(c, tasks.get_task(c, int(ref)))
            if kind == 'schedules':
                return scheduler.receivers(c, scheduler.get_schedule(c, int(ref)))
        except (LookupError, TypeError, ValueError):
            pass
        return []

    def need_for_deploy(c, kind, ref, mode, options):
        """What a deploy really does decides what it takes. run executes the script whatever the mode says and goes first in
        the items, so it cannot stand beside report (a dry run's permission) or remove (which needs no hosts.command)."""
        if options.get('run') and (mode != 'apply' or options.get('remove')):
            raise ValueError('run needs mode apply, and cannot be combined with remove')
        if mode == 'apply':
            need('deploy.apply')
            if kind == 'security':     # the sentinel is what catches ransomware, so taking it off a host is not an ordinary deploy
                need('security.sentinel')
        if options.get('destructive'):
            need('deploy.destructive')
        if mode == 'apply' and not options.get('remove'):
            need_for_commands(c, kind, ref)

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
            if kind == 'schedules':
                return scheduler.schedule_hash(c, scheduler.get_schedule(c, int(ref)))
            if kind == 'clamav':
                return clamav.digest(c, str(ref or ''))
            if kind == 'security':
                return security.digest(c, str(ref or ''))
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
        options = {k: bool(body[k]) for k in ('remove', 'paused', 'destructive', 'run', 'rearm') if body.get(k)}
        need_for_deploy(c, kind, ref, mode, options)
        try:
            items = deploy_items_for(c, kind, ref, mode, options)
        except receiving.NotEnrolled as exc:        # there is no unsigned way to a host, so this is the end of it, and the row says who asked
            core.audit(c, actor(), 'deploy.start', 'denied', None, {'kind': kind, 'ref': ref, 'mode': mode, 'receivers': exc.hosts, 'error': str(exc)[:500]})
            return jsonify(error=str(exc), hosts=exc.hosts), 409
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
        gid = deploy.start_group(db, items, who, after=lambda h: core.enqueue(h, who), title=title, **updates.group_options(kind, mode),
                                 kind=kind, ref=str(ref), mode=mode, options=options, digest=digest, report_group=report or None)
        hops, got = second_hops(c, kind, ref), send_receivers(c, kind, ref)
        core.audit(c, actor(), 'deploy.start', 'ok', None, {'kind': kind, 'ref': ref, 'mode': mode, 'group': gid, **({'second_hops': hops} if hops else {}), **({'receivers': got} if got else {})})
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
        need_for_deploy(c, g['kind'], g['ref'], g['mode'], g['options'])
        if engine.running(gid):
            return jsonify(error='that deploy is still running'), 409
        if g['kind'] not in ('jobs', 'shares', 'changes', 'tasks', 'schedules', updates.KIND, 'clamav', 'security'):
            raise ValueError('only plans and designs can be retried')
        items = deploy_items_for(c, g['kind'], g['ref'], g['mode'], g['options'])
        if g['kind'] != 'jobs':       # job keys are new on every apply, so a job's two hosts must get them together. A send's too
            left = set(engine.unfinished_hosts(c, gid))
            items = [it for it in items if it['host'] in left or it['kind'] == receiving.KIND]
        if not items:
            raise ValueError('every host of that deploy finished')
        who = actor()
        new = deploy.start_group(db, items, who, after=lambda h: core.enqueue(h, who), **updates.group_options(g['kind'], g['mode']),
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

    @web.post('/api/deploy/jobs/<jid>/<any("run", "dryrun", "verify", "pause", "resume", "cutover", "log", "snapshots", "dedupe"):verb>')
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

    def redraw_host(host: str):
        """The maps and the 3-2-1 matrix are built at scan time: after a job comes or goes they can't wait for the next scan."""
        scan_designs.pop(deploy.canonical(conn(), host), None)
        graph.rebuild_host(db, conn(), deploy.canonical(conn(), host))

    def job_hosts(runner: str, jid: str | None = None) -> set[str]:
        """The runner, and every scanned host its jobs (or just jid) pull from: an imported rsnapshot can back up other hosts."""
        known = {r[0].lower() for r in conn().all('SELECT hostname FROM hosts')}
        out = {runner}
        for j in jobs.overview(conn()):
            if (j['id'] == jid) if jid else fsmap.same_host(j['runner'] or '', runner):
                out |= {p['host'] for p in j.get('places') or [] if p['host'].lower() in known}
        return out

    @web.post('/api/deploy/jobs/<jid>/retention')
    @login_required
    @password_confirmed
    def api_deploy_job_retention(jid):
        res = snapjobs.retention(db, conn(), jid, json_body().get('keep'), actor())
        core.audit(conn(), actor(), 'deploy.job-retention', deploy.audit_outcome(res['status']), None, {'job': jid})
        return jsonify(res)

    @web.post('/api/deploy/jobs/<jid>/forget')
    @login_required
    @password_confirmed
    def api_deploy_job_forget(jid):
        hosts = job_hosts(jobs.get(conn(), jid)['runner'], jid)
        snapjobs.forget(conn(), jid)
        for h in hosts:
            redraw_host(h)
        core.audit(conn(), actor(), 'deploy.job-forget', 'ok', None, {'job': jid})
        return jsonify(forgotten=jid)

    @web.get('/api/deploy/snapjobs')
    @login_required
    def api_snapjobs():
        return jsonify(found=snapjobs.candidates(conn()))

    @web.get('/api/deploy/snapjobs/advice')
    @login_required
    def api_snapjobs_advice():
        return jsonify(snapjobs.advice_for(conn(), request.args.get('host', ''), request.args.get('path', '')))

    @web.post('/api/deploy/snapjobs/probe')
    @login_required
    @password_confirmed
    def api_snapjobs_probe():
        host = str(json_body().get('host', ''))
        found = snapjobs.probe(db, conn(), host, actor())
        for h in job_hosts(deploy.canonical(conn(), host)):
            redraw_host(h)
        core.audit(conn(), actor(), 'deploy.snapjobs-probe', 'ok', host, {'found': len(found)})
        return jsonify(found=snapjobs.candidates(conn()))

    @web.post('/api/deploy/snapjobs/import')
    @login_required
    @password_confirmed
    def api_snapjobs_import():
        body = json_body()
        host, tool, config = str(body.get('host', '')), str(body.get('tool', '')), str(body.get('config', ''))
        jid = snapjobs.import_job(conn(), host, tool, config, actor())
        for h in job_hosts(deploy.canonical(conn(), host), jid):
            redraw_host(h)
        core.audit(conn(), actor(), 'deploy.job-import', 'ok', host, {'job': jid, 'tool': tool, 'config': config})
        return jsonify(job=jid)

    @web.post('/api/deploy/snapjobs/snapper')
    @login_required
    @password_confirmed
    def api_snapjobs_snapper():
        body = json_body()
        host = str(body.get('host', ''))
        res = snapjobs.create_snapper(db, conn(), host, str(body.get('path', '')), str(body.get('name', '')), actor())
        if res['status'] == 'ok':
            redraw_host(host)
        core.audit(conn(), actor(), 'deploy.snapper-create', deploy.audit_outcome(res['status']), host, {'path': body.get('path'), 'name': body.get('name')})
        return jsonify(res)

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
        core.audit(conn(), actor(), 'deploy.settings.test', 'info', None, {})
        return jsonify(sent=alerts.send(alerts.get_setting(conn(), 'alerts'), 'StorageForge test alert',
                                        f'Sent by {current_user.username} from the Deploy tab.', 'ok', {'state': 'test'}))

    @web.route('/api/remote/nodes', methods=['GET', 'POST'])
    @login_required
    def api_remote_nodes():
        if request.method == 'GET':
            return jsonify(remotes.overview(conn()))
        stale = password_stale()         # its script runs as root on the node, and holds a key
        if stale:
            return stale
        body = json_body()
        return jsonify(remotes.add(db, conn(), body.get('name'), body.get('endpoint'), actor()))

    @web.post('/api/remote/nodes/<int:node_id>/adopt')
    @login_required
    def api_remote_adopt(node_id):
        stale = password_stale()
        if stale:
            return stale
        try:
            return jsonify(remotes.adopt(db, conn(), node_id, actor(), lambda addr: core.enqueue(addr, actor())))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.delete('/api/remote/nodes/<int:node_id>')
    @login_required
    def api_remote_revoke(node_id):
        stale = password_stale()
        if stale:
            return stale
        try:
            return jsonify(remotes.revoke(db, conn(), node_id, actor()))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

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

    @web.post('/api/jobs/state')
    @limiter.limit('120 per minute')
    def api_jobs_state():
        auth = request.headers.get('Authorization', '')
        jid = jobs.job_for_token(conn(), auth[7:].strip() if auth.startswith('Bearer ') else '')
        if not jid:
            return jsonify(error='unknown job token'), 401
        body = json_body()
        if body.get('job') != jid:
            return jsonify(error='this token belongs to another job'), 403
        jobs.ingest_state(conn(), body)
        return jsonify(ok=True)

    routes_scheduler.register(web, ctx)

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
        v = hostconfig.get(conn(), cid) if cid else hostconfig.for_rebuild(conn(), host)
        if not v:
            return jsonify(error=f'nothing captured for {host}: scan it first'), 404
        core.audit(conn(), actor(), 'hostconfig.script', 'ok', v['host'], {'version': v['config_id']})
        return Response(site.stamp(conn(), reinstall.script(v)).encode('utf-8', 'surrogateescape'), mimetype='text/x-shellscript',
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
        last = conn().all("""SELECT action, outcome, ts_us, detail_json FROM audit_log WHERE actor = 'system' AND action = 'backup.create'
                               ORDER BY audit_id DESC LIMIT 1""")
        copied = conn().all("""SELECT outcome, ts_us, detail_json FROM audit_log WHERE action = 'backup.copy' ORDER BY audit_id DESC LIMIT 1""")
        return jsonify(backups=backup.listing() if db.dialect == 'sqlite' else [], hour=BACKUP_HOUR, keep=BACKUP_KEEP,
                       full_keep=BACKUP_FULL, external=db.dialect != 'sqlite', target=alerts.get_setting(conn(), 'backup.target'),
                       nightly={'outcome': last[0][1], 'at': last[0][2] // 1000000} if last else None,
                       copy={'outcome': copied[0][0], 'at': copied[0][1] // 1000000, 'detail': json.loads(copied[0][2] or '{}')} if copied else None)

    @web.put('/api/backups/target')
    @login_required
    @password_confirmed
    def api_backup_target():
        body = json_body()
        host, path = str(body.get('host') or '').strip(), str(body.get('path') or '').strip()
        if bool(host) != bool(path):
            raise ValueError('give both a host and a folder, or neither to stop copying')
        if path and not re.fullmatch(r'/[A-Za-z0-9._/-]{1,200}', path):
            raise ValueError('the folder must be an absolute path of letters, digits and . _ - /')
        alerts.set_setting(conn(), 'backup.target', {'host': host, 'path': path} if host else None, actor())
        core.audit(conn(), actor(), 'backup.target', 'ok', host or None, {'path': path})
        return jsonify(target={'host': host, 'path': path} if host else None)

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
        if kind == 'essentials':
            res['copy_error'] = core.copy_off(conn(), res['path'], actor())
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
                remember(folder_cache, key, result, latest)
        return result

    dir_kept: list = [None]                   # (scan id, folder index): listings and comparisons share it. Replaced whole, never edited
    dir_build = threading.Lock()

    def kept_dir_index():
        kept = dir_kept[0]
        return kept[1] if kept and kept[0] == conn().scalar('SELECT max(scan_id) FROM scans') else None

    def build_dir_index(host):
        """One build at a time. A scan changes rows as it goes, so nothing is kept while one runs, as in folder_result."""
        with dir_build:
            if (index := kept_dir_index()) is not None:
                return index
            latest, running = conn().all("SELECT max(scan_id), count(CASE WHEN status = 'running' THEN 1 END) FROM scans")[0]
            if running:
                return folders.dir_index(conn(), host)
            dir_kept[0] = None                # the old one goes first: two at once is a lot of memory
            dir_kept[0] = (latest, folders.dir_index(conn()))
            return dir_kept[0][1]

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
                                     lambda: folders.duplicate_folders(conn(), host, min_files, min_size, limit=200, index=build_dir_index(host))))

    def filemap_result(host, min_size, system, with_folders):
        def compute():
            twins = None
            if with_folders:
                key = ('dupes', host, 3, min_size) if not system else ('dupes-system', host, 3, min_size)
                twins = folder_result(key, lambda: folders.duplicate_folders(conn(), host, 3, min_size, limit=200, include_system=system, index=build_dir_index(host)))
            return filemap.build(conn(), host, min_size, system, twins)
        # its job lines change without a scan: importing or removing a job has to show now
        job_mark = tuple(conn().all('SELECT count(*), max(deployed_at), max(removed_at) FROM jobs')[0])
        return folder_result(('filemap', host, min_size, system, with_folders, json.dumps(folders.ignore_lists(conn()), sort_keys=True), job_mark), compute)

    @web.get('/api/filemap')
    @login_required
    def api_filemap():
        return jsonify(filemap_result(request.args.get('host') or None, parse_size(request.args.get('min_size') or '1MiB'),
                                      bool(request.args.get('system')), bool(request.args.get('folders'))))

    def warm_filemap():
        """The file map as the page first asks for it, so nobody waits for the folder comparison after a scan."""
        with web.app_context():
            if not conn().scalar("SELECT count(*) FROM scans WHERE status = 'running'"):   # the last one to finish wakes this again
                filemap_result(None, parse_size('1MiB'), False, True)
    web.warm_filemap = warm_filemap

    @web.route('/api/files/ignore', methods=['GET', 'PUT'])
    @login_required
    def api_files_ignore():
        if request.method == 'PUT':
            body = json_body()
            paths, host = body.get('paths'), str(body.get('host') or '')
            if not isinstance(paths, list) or not all(isinstance(x, str) and '\n' not in x for x in paths) or len(paths) > 2000:
                return jsonify(error='paths must be a list of paths or path fragments'), 400
            folders.save_ignore(conn(), host, paths, actor())
            core.audit(conn(), actor(), 'files.ignore', 'ok', host or None, {'paths': len(paths)})
            scan_designs.clear()              # broken links are left out when a design is read from the scan
            names = [host] if host and scanned(host) else [r[0] for r in conn().all('SELECT hostname FROM hosts')]

            def rebuild():                    # a graph per host: too long to hold a request and a web thread
                c = db.connect()
                try:
                    for name in names:
                        graph.rebuild_host(db, c, name)
                except Exception:
                    errlog.trace()
                finally:
                    c.close()
            threading.Thread(target=rebuild, name='ignore-rebuild', daemon=True).start()
        return jsonify(ignore=folders.ignore_lists(conn()), builtin_dirs=[*folders.NOISE_DIRS, *filemap.APP_DIRS], builtin_names=sorted(folders.NOISE_NAMES))

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

    @web.get('/api/scans/signing')
    @login_required
    def api_scans_signing():
        from . import scansign
        pinned = [dict(zip(('address', 'fingerprint', 'pinned_at', 'how'), r))
                  for r in conn().all('SELECT address, fingerprint, pinned_at, how FROM scan_signers ORDER BY address')]
        return jsonify(require=scansign.required(conn()), hosts=scansign.status(conn()), pinned=pinned)

    @web.put('/api/scans/signing')
    @login_required
    @password_confirmed
    def api_scans_signing_set():
        from . import scansign
        need = bool(json_body().get('require'))
        alerts.set_setting(conn(), scansign.REQUIRE, need, actor())
        core.audit(conn(), actor(), 'scans.require_signed', 'ok', None, {'require': need})
        return jsonify(require=need)

    @web.delete('/api/scans/signing/<path:addr>')
    @login_required
    @password_confirmed
    def api_scans_signing_forget(addr):
        from . import scansign
        host, _, port = addr.rpartition(':') if addr.count(':') == 1 else (addr, '', '22')
        gone = scansign.forget(conn(), host or addr, int(port or 22))
        core.audit(conn(), actor(), 'scans.signing_key.forget', 'ok' if gone else 'failed', host or addr, {'address': addr})
        return jsonify(forgotten=gone)

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

    def quiet_links(host: str, links) -> list:
        ignore = folders.ignore_lists(conn())
        return [l for l in links or [] if not (l.get('health') == 'crit' and folders.is_ignored(host, l.get('path') or '', ignore))]

    @web.get('/api/planner/design')
    @login_required
    def api_planner_design():
        host, source = request.args.get('host', '').strip(), request.args.get('source') or 'saved'
        if not host:
            raise ValueError('give host')
        saved = graph.stored_blueprint(conn(), host)
        saved_at = conn().scalar('SELECT imported_at FROM blueprints WHERE hostname = :h', {'h': host})
        offsite = moves.host_slug(host) in protection.offsite_hosts(conn())
        if source == 'saved' and saved:
            saved['links'] = quiet_links(host, saved.get('links'))
            saved['protection'] = protection.overlay(conn(), host, saved.get('protection') or [])
            return jsonify(host=host, source='saved', saved_at=saved_at, scanned=scanned(host), offsite=offsite, blueprint=saved, shares_deployed=shares.in_sync(conn(), host))
        if not scanned(host):
            return jsonify(error=f'{host} has no saved design and has not been scanned'), 404
        bp = blueprint.merge_intent(scan_design(host), saved)
        bp['links'] = quiet_links(host, bp.get('links'))
        bp['protection'] = protection.overlay(conn(), host, bp['protection'])
        return jsonify(host=host, source='scan', saved_at=saved_at, scanned=True, offsite=offsite, blueprint=bp, shares_deployed=shares.in_sync(conn(), host))

    @web.put('/api/planner/offsite')
    @login_required
    def api_planner_offsite():
        body = json_body()
        host, off = str(body.get('host') or '').strip(), bool(body.get('offsite'))
        if not host:
            raise ValueError('give host')
        protection.set_offsite(conn(), host, off, actor())
        core.audit(conn(), actor(), 'planner.offsite', 'ok', host, {'offsite': off})
        return jsonify(host=host, offsite=off)

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
        if bp.get('protection'):             # a design as loaded carries job names, which hold arrows: never part of a save
            bp['protection'] = protection.as_typed(bp['protection'])
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
               for j in jobs.overview(c) if same_host(j['runner'] or '', host) or same_host(j['source'] or '', host)
               or any(same_host(p['host'], host) for p in j.get('places') or [])]
    acc = next(iter(access.status(c, host, limit=0)), None)
    return {'host': host, 'changes': staged, 'moves': moving, 'shares': designed, 'jobs': running,
            'deployed': [{'kind': d['kind'], 'ref': d['ref'], 'at': d['at']} for d in deploy.deployed(c) if same_host(d['host'], host)],
            'drift': [x for x in alerts.drift(c) if same_host(x['host'], host)],
            'unreadable': acc['denied_total'] if acc else None, 'access': acc['access'] if acc else None}


def serve(db: Database, host: str, port: int, scan_interval: int | None, parallel: int = 4):
    from waitress import serve as waitress_serve
    server_lock = reset.hold_server_lock(db)     # noqa: F841  a reset refuses while this is held; freed when the process ends
    conn = db.connect()
    try:
        site.ensure(conn)
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
    web_core = App(db, scan_interval, parallel)
    web = create_app(web_core, session_secret_from_env(), secure, hops,
                     os.environ.get('STORAGEFORGE_PROXY_HOST', ''))

    def warm():
        while True:
            try:
                web.warm_filemap()
            except Exception:
                errlog.trace()
            web_core.scan_done.wait()
            web_core.scan_done.clear()
    threading.Thread(target=warm, name='filemap-warm', daemon=True).start()
    print(f'StorageForge {__version__} listening on http://{host}:{port}', file=sys.stderr, flush=True)
    waitress_serve(web, host=host, port=port, threads=8, ident='StorageForge', _quiet=True)
