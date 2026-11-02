"""ClamAV on hosts: a deployed scan on a timer, its results read back by scans, and quarantine and restore on request.

A deploy installs ClamAV and a timer that scans as an unprivileged account allowed only to read (CAP_DAC_READ_SEARCH),
with no network. A scan only reports: last.tsv is replaced after each run and StorageForge scans read it, so a
detection appears after the next scan of the host, or at once with Collect. Nothing here changes a file unless someone
asks. Quarantine runs through storageforge-run, checks the file with ClamAV again first, and moves it to a root-only
folder that restore moves it back from. Nothing is ever deleted.

Results come from the host they describe, so a compromised host can lie about itself. That is why quarantine scans
the file again instead of trusting the path it was given.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import re
import shlex
import time
import uuid

from . import alerts
from .db import Conn
from .scriptkit import HELPERS, PACKAGES

STATE = '/var/lib/storageforge/clamav'
QUARANTINE = '/var/lib/storageforge/quarantine'
SCANNER = '/usr/local/sbin/storageforge-clamscan'
PATHS = '/etc/storageforge/clamav.paths'
UNITS = '/etc/systemd/system'
MANAGED = '/var/lib/storageforge/managed'
USER = 'storageforge-clamav'
SCHEDULES = {'daily': '*-*-* 03:15:00', 'weekly': 'Sun *-*-* 03:15:00', 'monthly': '*-*-01 03:15:00'}
SYSTEM_PATHS = ('/bin', '/sbin', '/lib', '/lib32', '/lib64', '/usr', '/boot', '/etc')
UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
QID_RE = re.compile(r'[0-9a-f]{32}')
SIG_RE = re.compile(r'[A-Za-z0-9._:+-]{1,200}')
SIGNATURES_OLD = 7 * 86400
MAX_FOUND = 5000
EXCLUDE_DIRS = r'^/(proc|sys|dev|run)(/|$)'
PACKAGE_NAMES = {'apt-get': 'clamav clamav-freshclam', 'dnf': 'clamav clamav-update', 'yum': 'clamav clamav-update',
                 'zypper': 'clamav', 'pacman': 'clamav'}

SCAN_SCRIPT = r"""#!/bin/bash
# Written by StorageForge. Only reads: a detection is reported, never touched.
set -u
STATE=@STATE@ PATHS=@PATHS@ QUAR=@QUAR@ MAX=@MAX@
umask 022
run=$(cat /proc/sys/kernel/random/uuid) start=$(date +%s) raw=$(mktemp "$STATE/.raw.XXXXXX") out=$(mktemp "$STATE/.out.XXXXXX")
trap 'rm -f "$raw" "$out"' EXIT
mapfile -t roots <"$PATHS"
clamscan --recursive --infected --cross-fs=no --stdout "--exclude-dir=@EXCLUDE@" "--exclude-dir=^$QUAR(/|$)" \
  '--exclude-dir=/\.snapshots(/|$)' '--exclude-dir=/\.zfs(/|$)' "${roots[@]}" >"$raw" 2>/dev/null
rc=$?
scanned=$(sed -n 's/^Scanned files: *\([0-9][0-9]*\).*/\1/p' "$raw" | head -n 1)
version=$(clamscan --version 2>/dev/null | tr -d '\t\r' | head -n 1)
printf 'run\t%s\t%s\t%s\t%s\t%s\t%s\n' "$run" "$start" "$(date +%s)" "$rc" "${scanned:-0}" "$version" >"$out"
n=0
while IFS= read -r line; do
  [[ $line == *' FOUND' ]] || continue
  ((n++ < MAX)) || break
  sig=${line% FOUND}; path=${sig%: *}; sig=${sig##*: }
  printf 'found\t%s\t%s\n' "$(printf %s "$path" | base64 -w0)" "$(tr -cd 'A-Za-z0-9._:+-' <<<"$sig")" >>"$out"
done <"$raw"
chmod 0644 "$out"
mv -f "$out" "$STATE/last.tsv"
"""

SERVICE = """[Unit]
Description=StorageForge ClamAV scan (reports only)
After=network-online.target

[Service]
Type=oneshot
User=@USER@
ExecStart=@SCANNER@
AmbientCapabilities=CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
PrivateNetwork=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=@STATE@
Nice=19
IOSchedulingClass=idle
CPUWeight=10
OOMScoreAdjust=900
"""

TIMER = """[Unit]
Description=StorageForge ClamAV scan timer

[Timer]
OnCalendar=@CALENDAR@
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
"""

INSTALL = r"""
STATE=@STATE@ SCANNER=@SCANNER@ PATHS=@PATHS@ UNITS=@UNITS@ MANAGED=@MANAGED@ U=@USER@
APPLY=0 REMOVE=0 RUN=0
for a in "$@"; do case $a in --apply) APPLY=1 ;; --uninstall) APPLY=1 REMOVE=1 ;; --run) RUN=1 ;; *) echo "unknown option: $a" >&2; exit 2 ;; esac; done

if ((RUN)); then
  systemctl start --no-block sf-clamav.service && echo "started the scan: its result appears after the next StorageForge scan of this host"
  exit
fi

if ((REMOVE)); then
  section "Remove the ClamAV scan"
  systemctl disable --now sf-clamav.timer 2>/dev/null || true
  rm -f "$UNITS/sf-clamav.service" "$UNITS/sf-clamav.timer" "$SCANNER" "$PATHS" "$MANAGED/clamav.sha256" "$STATE/last.tsv"
  systemctl daemon-reload 2>/dev/null || true
  ok "scan removed; the ClamAV package stays installed"
  q=$(find @QUAR@ -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
  ((q == 0)) || info "$q file(s) stay in quarantine at @QUAR@"
  finished; exit
fi

section "ClamAV"
mem=$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null)
if ((${mem:-0} > 0 && ${mem:-0} < 2048)); then
  conflict "only ${mem} MiB of memory: ClamAV loads its signatures into about 1 GiB for each scan"
  ((APPLY == 0)) || exit 1
else
  ok "${mem:-unknown} MiB of memory"
fi
if command -v clamscan >/dev/null; then
  ok "clamscan: $(clamscan --version | head -n 1)"
elif ((APPLY)); then
  m=$(pm)
  case $m in
@CASES@
    *) conflict "no package manager I know: install ClamAV by hand and deploy again"; exit 1 ;;
  esac
  for p in $pkgs; do doing "install $p with $m"; install_pkg "$m" "$p"; done
  ok "clamscan installed"
else
  missing "ClamAV is not installed: --apply installs it"
fi

for f in /etc/freshclam.conf /etc/clamav/freshclam.conf; do
  if ((APPLY)) && [[ -f $f ]] && grep -q '^Example' "$f"; then sed -i 's/^Example/#Example/' "$f"; fi
done

section "Scan"
info "folders: $(printf '%s ' @ROOTS@)"
info "schedule: @SCHEDULE@"
if ((APPLY == 0)); then
  [[ -f $UNITS/sf-clamav.timer ]] && ok "scan timer is installed" || missing "scan timer: --apply installs it"
  [[ -r $STATE/last.tsv ]] && ok "last result: $(head -n 1 "$STATE/last.tsv" | cut -f4,5 --output-delimiter=' finished at, exit code ')"
  finished; exit
fi

id "$U" >/dev/null 2>&1 || { doing "create the account $U"; useradd -r -M -s /usr/sbin/nologin "$U" 2>&1 || useradd -r -M -s /sbin/nologin "$U"; }
mkdir -p "$STATE" "$MANAGED" "$(dirname "$PATHS")"
chown "$U" "$STATE"; chmod 0755 "$STATE"
install -m 0755 /dev/null "$SCANNER"
cat >"$SCANNER" <<'SF_SCANNER'
@SCAN_SCRIPT@SF_SCANNER
printf '%s\n' @ROOTS@ >"$PATHS"
chmod 0644 "$PATHS"
cat >"$UNITS/sf-clamav.service" <<'SF_SERVICE'
@SERVICE@SF_SERVICE
cat >"$UNITS/sf-clamav.timer" <<'SF_TIMER'
@TIMER@SF_TIMER
sha256sum "$SCANNER" "$PATHS" "$UNITS/sf-clamav.service" "$UNITS/sf-clamav.timer" >"$MANAGED/clamav.sha256"
chmod 0644 "$MANAGED/clamav.sha256"

updater=
for s in clamav-freshclam.service; do systemctl cat "$s" >/dev/null 2>&1 && updater=$s; done
if [[ -n $updater ]]; then
  systemctl enable --now "$updater" 2>&1 && ok "signature updates: $updater"
else
  conflict "no freshclam service here: signatures will not update until you set one up"
fi
db=$(find /var/lib/clamav -maxdepth 1 \( -name '*.cvd' -o -name '*.cld' \) 2>/dev/null | head -n 1)
if [[ -z $db ]] && ! systemctl is-active -q "${updater:-none}" 2>/dev/null; then
  doing "download signatures"; freshclam --quiet 2>&1 || missing "signatures did not download: scans fail until they do"
elif [[ -z $db ]]; then
  info "the signature service is downloading them; scans fail until it has"
fi
systemctl daemon-reload
systemctl enable --now sf-clamav.timer 2>&1 && ok "scan timer on"
finished
"""

ACTION_HEAD = r"""
QUAR=@QUAR@ QID=@QID@ B64=@B64@
APPLY=0
for a in "$@"; do case $a in --apply) APPLY=1 ;; *) echo "unknown option: $a" >&2; exit 2 ;; esac; done
q=$QUAR/$QID
path=$(base64 -d <<<"$B64"; echo x); path=${path%x}
[[ $path == /* && $path != *'/../'* ]] || { conflict "not an absolute path"; exit 1; }
"""

QUARANTINE_BODY = r"""
SYSTEM=@SYSTEM@ SIG=@SIG@
if [[ -e $q/file ]]; then
  [[ ! -e $path ]] && { ok "already in quarantine"; echo "QUARANTINED $QID $(sed -n 's/^sha256=//p' "$q/meta")"; exit 0; }
  conflict "this quarantine id already holds a file, and $path exists too"; exit 1
fi
[[ ! -L $path ]] || { conflict "$path is a symlink now: scan again"; exit 1; }
[[ -f $path ]] || { conflict "$path is gone, or not a regular file"; exit 1; }
if ((SYSTEM == 0)); then
  case $path in /bin/*|/sbin/*|/lib/*|/lib32/*|/lib64/*|/usr/*|/boot/*|/etc/*)
    conflict "$path is a system path: moving it can stop this host from booting. Allow system paths to go ahead"; exit 1 ;;
  esac
fi
rc=0; clamscan --no-summary --infected "$path" >/dev/null 2>&1 || rc=$?
case $rc in
  1) ok "ClamAV still detects $path" ;;
  0) conflict "ClamAV no longer detects $path: it was left where it is"; exit 1 ;;
  *) conflict "ClamAV could not check $path (exit code $rc): it was left where it is"; exit 1 ;;
esac
links=$(stat -c %h "$path")
((links == 1)) || info "$path has $links hard links: the others stay where they are"
if command -v fuser >/dev/null && fuser -s "$path" 2>/dev/null; then
  info "a process has $path open. Moving the file does not stop that process: look at it yourself"
fi
if ((APPLY == 0)); then
  doing "would move $path to $q"; finished; exit 0
fi
sha=$(sha256sum "$path" | cut -d' ' -f1)
mkdir -p -m 0700 "$QUAR"; chmod 0700 "$QUAR"
mkdir -m 0700 "$q"
{ printf 'b64=%s\nmode=%s\nowner=%s\nsignature=%s\nsha256=%s\nat=%s\n' "$B64" "$(stat -c %a "$path")" "$(stat -c %u:%g "$path")" "$SIG" "$sha" "$(date +%s)"; } >"$q/meta"
mv -- "$path" "$q/file"
chmod 000 "$q/file"
ok "moved to quarantine"
echo "QUARANTINED $QID $sha"
"""

RESTORE_BODY = r"""
[[ -e $q/file ]] || { conflict "quarantine holds nothing under $QID"; exit 1; }
[[ $(sed -n 's/^b64=//p' "$q/meta") == "$B64" ]] || { conflict "that quarantined file came from another path"; exit 1; }
[[ ! -e $path && ! -L $path ]] || { conflict "$path exists again: restoring would overwrite it"; exit 1; }
[[ -d ${path%/*}/ ]] || { conflict "the folder of $path is gone: make it first"; exit 1; }
if ((APPLY == 0)); then
  doing "would move it back to $path"; finished; exit 0
fi
mode=$(sed -n 's/^mode=//p' "$q/meta") owner=$(sed -n 's/^owner=//p' "$q/meta")
[[ $mode =~ ^[0-7]{3,4}$ && $owner =~ ^[0-9]+:[0-9]+$ ]] || { conflict "the quarantine record is damaged: restore it by hand from $q"; exit 1; }
mv -- "$q/file" "$path"
chown "$owner" "$path"; chmod "$mode" "$path"
rm -f "$q/meta"; rmdir "$q"
ok "restored"
echo "RESTORED $QID"
"""


def _head() -> str:
    return '#!/usr/bin/env bash\n# Written by StorageForge. With no flags it only reports.\nset -eu\n' + HELPERS


def default_paths(conn: Conn, host: str) -> list[str]:
    """The mounts scans walk: real local filesystems, each scanned without crossing into the next."""
    rows = conn.all("""SELECT m.mount_point FROM mounts m JOIN hosts h ON h.host_id = m.host_id
                       WHERE lower(h.hostname) = lower(:h) AND m.scan_state = 'indexed' ORDER BY m.mount_point""", {'h': host})
    return [r[0] for r in rows] or ['/']


def get_config(conn: Conn, host: str) -> dict:
    saved = alerts.get_setting(conn, f'clamav.host:{host.lower()}') or {}
    return {'schedule': saved.get('schedule') or 'weekly', 'paths': saved.get('paths') or default_paths(conn, host),
            'custom_paths': bool(saved.get('paths'))}


def save_config(conn: Conn, host: str, body: dict, actor: str) -> dict:
    schedule = str(body.get('schedule') or 'weekly')
    if schedule not in SCHEDULES:
        raise ValueError('the schedule is daily, weekly or monthly')
    paths = [str(p).strip() for p in body.get('paths') or [] if str(p).strip()]
    for p in paths:
        if not p.startswith('/') or '/../' in p + '/' or any(ord(c) < 32 for c in p) or len(p) > 1000:
            raise ValueError(f'not an absolute path: {p[:80]}')
    alerts.set_setting(conn, f'clamav.host:{host.lower()}', {'schedule': schedule, 'paths': paths}, actor)
    return get_config(conn, host)


def install_script(config: dict) -> str:
    cases = '\n'.join(f'    {m}) pkgs={shlex.quote(p)} ;;' for m, p in PACKAGE_NAMES.items())
    scan = SCAN_SCRIPT
    for k, v in (('@STATE@', STATE), ('@PATHS@', PATHS), ('@QUAR@', QUARANTINE), ('@MAX@', str(MAX_FOUND)), ('@EXCLUDE@', EXCLUDE_DIRS)):
        scan = scan.replace(k, v)
    service = SERVICE.replace('@USER@', USER).replace('@SCANNER@', SCANNER).replace('@STATE@', STATE)
    timer = TIMER.replace('@CALENDAR@', SCHEDULES[config['schedule']])
    body = INSTALL
    for k, v in (('@STATE@', STATE), ('@SCANNER@', SCANNER), ('@PATHS@', PATHS), ('@UNITS@', UNITS), ('@MANAGED@', MANAGED), ('@USER@', USER),
                 ('@QUAR@', QUARANTINE), ('@CASES@', cases), ('@SCHEDULE@', config['schedule']), ('@SCAN_SCRIPT@', scan), ('@SERVICE@', service),
                 ('@TIMER@', timer), ('@ROOTS@', ' '.join(shlex.quote(p) for p in config['paths']))):
        body = body.replace(k, v)
    return _head() + PACKAGES + body


def digest(conn: Conn, host: str) -> str:
    return hashlib.sha256(json.dumps(install_script(get_config(conn, host))).encode()).hexdigest()[:16]


def deploy_items(db, conn: Conn, host: str, mode: str, actor: str, run_now: bool = False, remove: bool = False) -> list[dict]:
    from . import deploy
    name = deploy.canonical(conn, host)
    if not conn.scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': name}):
        raise ValueError(f'{host} has not been scanned')
    config = get_config(conn, name)
    text = install_script(config)
    if run_now:
        return [{'host': name, 'script': text, 'args': ['--run'], 'kind': 'clamav', 'ref': name, 'mode': 'apply'}]
    if mode != 'apply':
        return [{'host': name, 'script': text, 'args': [], 'kind': 'clamav', 'ref': name, 'mode': 'report'}]

    def mark(_res):
        c = db.connect()
        try:
            if remove:
                c.execute("DELETE FROM deployed WHERE host = :h AND kind = 'clamav'", {'h': name})
            else:
                deploy.mark_deployed(c, name, 'clamav', 'clamav', digest(c, name), {'schedule': config['schedule'], 'paths': config['paths']}, actor)
        finally:
            c.close()
    return [{'host': name, 'script': text, 'args': ['--uninstall' if remove else '--apply'], 'kind': 'clamav', 'ref': name, 'mode': 'apply', 'on_ok': mark}]


# ── results ─────────────────────────────────────────────────────────
def _signature_time(version: str) -> int | None:
    """From "ClamAV 1.0.7/27000/Sat Oct 31 08:30:00 2026"."""
    try:
        return int(dt.datetime.strptime(' '.join(version.rsplit('/', 1)[1].split()), '%a %b %d %H:%M:%S %Y').replace(tzinfo=dt.timezone.utc).timestamp())
    except (IndexError, ValueError):
        return None


def parse_report(text: str) -> tuple[dict, list[tuple[str, str, str]]] | None:
    """last.tsv: the run line, then (path_b64, path, signature) per detection. None if it cannot be read."""
    lines = (text or '').splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith('run\t')), None)   # the runner may print first
    if start is None:
        return None
    lines = lines[start:]
    head = lines[0].split('\t')
    try:
        if head[0] != 'run' or not UUID_RE.fullmatch(head[1]):
            return None
        run = {'run': head[1], 'start': int(head[2]), 'end': int(head[3]), 'rc': int(head[4]), 'scanned': int(head[5]),
               'version': head[6][:200] if len(head) > 6 else ''}
    except (IndexError, ValueError):
        return None
    if max(run['start'], run['end']) > time.time() + 600:      # a forged "clean" dated ahead would hide later runs
        return None
    found = []
    for line in lines[1:MAX_FOUND + 1]:
        f = line.split('\t')
        if len(f) != 3 or f[0] != 'found' or not SIG_RE.fullmatch(f[2]):
            continue
        try:
            raw = base64.b64decode(f[1], validate=True)
        except (binascii.Error, ValueError):
            continue
        if raw.startswith(b'/') and b'\0' not in raw and len(raw) <= 4096:
            found.append((f[1], raw.decode('utf-8', 'replace'), f[2]))
    return run, found


def ingest(conn: Conn, host: str, text: str, via: str = 'scan') -> bool:
    """One host's last result. Returns False if already seen or unreadable. Only a finished run clears what it no longer
    reports: a scan cut short, or one that read nothing, must not close a detection."""
    parsed = parse_report(text)
    if not parsed:
        return False
    run, found = parsed
    if conn.scalar('SELECT count(*) FROM clamav_runs WHERE run_uuid = :u', {'u': run['run']}):
        return False
    now = int(time.time())
    complete = run['rc'] in (0, 1) and run['scanned'] > 0
    with conn.tx():
        conn.execute("""INSERT INTO clamav_runs (run_uuid, host, started_at, finished_at, exit_code, scanned, found, version, signatures_at, via, received_at)
                        VALUES (:u, :h, :s, :e, :rc, :n, :f, :v, :sa, :via, :t)""",
                     {'u': run['run'], 'h': host, 's': run['start'], 'e': run['end'], 'rc': run['rc'], 'n': run['scanned'], 'f': len(found),
                      'v': run['version'], 'sa': _signature_time(run['version']), 'via': via, 't': now})
        existing = {(r[1], r[2]): r[0] for r in conn.all("""SELECT detection_id, path_b64, signature FROM clamav_detections
                                                            WHERE host = :h AND state IN ('open', 'gone')""", {'h': host})}
        seen = set()
        for b64, path, sig in found:
            seen.add((b64, sig))
            if (b64, sig) in existing:
                conn.execute("UPDATE clamav_detections SET state = 'open', last_seen = :t WHERE detection_id = :i", {'t': now, 'i': existing[(b64, sig)]})
            else:
                conn.execute("""INSERT INTO clamav_detections (host, path_b64, path, signature, state, ignored, first_seen, last_seen)
                                VALUES (:h, :b, :p, :s, 'open', 0, :t, :t)""", {'h': host, 'b': b64, 'p': path, 's': sig, 't': now})
        if complete:
            for key, did in existing.items():
                if key not in seen:
                    conn.execute("UPDATE clamav_detections SET state = 'gone' WHERE detection_id = :i AND state = 'open'", {'i': did})
    return True


def add_found(conn: Conn, host: str, text: str) -> int:
    """Detections from a scan of only some files: found\\tpath_b64\\tsignature lines. Unlike ingest this closes nothing,
    since it says nothing about the files it did not read. Returns how many are new."""
    now, new = int(time.time()), 0
    known = {(r[1], r[2]): r[0] for r in conn.all('SELECT detection_id, path_b64, signature FROM clamav_detections WHERE host = :h', {'h': host})}
    for line in (text or '').splitlines():
        f = line.split('\t')
        if len(f) != 3 or f[0] != 'found' or not SIG_RE.fullmatch(f[2]):
            continue
        try:
            raw = base64.b64decode(f[1], validate=True)
        except (binascii.Error, ValueError):
            continue
        if not raw.startswith(b'/') or b'\0' in raw or len(raw) > 4096:
            continue
        if (f[1], f[2]) in known:
            conn.execute("UPDATE clamav_detections SET last_seen = :t, state = CASE WHEN state = 'gone' THEN 'open' ELSE state END WHERE detection_id = :i", {'t': now, 'i': known[(f[1], f[2])]})
        else:
            conn.execute("""INSERT INTO clamav_detections (host, path_b64, path, signature, state, ignored, first_seen, last_seen)
                            VALUES (:h, :b, :p, :s, 'open', 0, :t, :t)""", {'h': host, 'b': f[1], 'p': raw.decode('utf-8', 'replace'), 's': f[2], 't': now})
            new += 1
    return new


def detections(conn: Conn, host: str | None = None, include_closed: bool = False) -> list[dict]:
    where = ["(lower(host) = lower(:h))"] if host else []
    if not include_closed:
        where.append("state IN ('open', 'quarantined')")
    rows = conn.all(f"""SELECT detection_id, host, path, signature, state, ignored, ignore_reason, quarantine_id, sha256, first_seen, last_seen, handled_by, handled_at
                        FROM clamav_detections {'WHERE ' + ' AND '.join(where) if where else ''}
                        ORDER BY ignored, CASE state WHEN 'open' THEN 0 WHEN 'quarantined' THEN 1 ELSE 2 END, host, path LIMIT 2000""", {'h': host})
    keys = ('id', 'host', 'path', 'signature', 'state', 'ignored', 'ignore_reason', 'quarantine_id', 'sha256', 'first_seen', 'last_seen', 'handled_by', 'handled_at')
    out = [dict(zip(keys, r)) for r in rows]
    for d in out:
        d['ignored'] = bool(d['ignored'])
        d['system_path'] = is_system_path(d['path'])
    return out


def is_system_path(path: str) -> bool:
    return any(path.startswith(p + '/') for p in SYSTEM_PATHS)


def last_run(conn: Conn, host: str) -> dict | None:
    rows = conn.all("""SELECT started_at, finished_at, exit_code, scanned, found, version, signatures_at FROM clamav_runs
                       WHERE lower(host) = lower(:h) ORDER BY finished_at DESC LIMIT 1""", {'h': host})
    if not rows:
        return None
    return dict(zip(('started_at', 'finished_at', 'exit_code', 'scanned', 'found', 'version', 'signatures_at'), rows[0]))


def hosts(conn: Conn, host: str | None = None) -> list[dict]:
    from . import deploy
    marks = {d['host']: d for d in deploy.deployed(conn, kind='clamav')}
    out = []
    for (name,) in conn.all('SELECT hostname FROM hosts ORDER BY hostname'):
        if host and name.lower() != host.lower():
            continue
        out.append({'host': name, 'installed': name in marks, 'deploy_ready': deploy.ready(conn, name), 'config': get_config(conn, name), 'last_run': last_run(conn, name)})
    return out


def problems(conn: Conn, now: float | None = None) -> dict:
    """One alert per signature per host, however many copies. Ignored ones stay quiet."""
    from . import deploy, jobs
    now = now if now is not None else time.time()
    out: dict = {}
    groups: dict = {}
    for host, path, sig in conn.all("SELECT host, path, signature FROM clamav_detections WHERE state = 'open' AND ignored = 0 ORDER BY path"):
        groups.setdefault((host, sig), []).append(path)
    for (host, sig), paths in groups.items():
        where = '; '.join(paths[:10]) + (f'; and {len(paths) - 10} more' if len(paths) > 10 else '')
        out[f'clamav:{host}:{sig}'] = ('clamav', f'{host}:{sig}', f'ClamAV found {sig} on {host}', where, 'crit')
    for d in deploy.deployed(conn, kind='clamav'):
        host, run = d['host'], last_run(conn, d['host'])
        if run and (run['exit_code'] not in (0, 1, 2) or not run['scanned']):
            out[f'clamav-failed:{host}'] = ('clamav-failed', host, f'ClamAV scan failed on {host}', f'exit code {run["exit_code"]}, {run["scanned"]} files scanned', 'crit')
        last = (run or {}).get('finished_at') or d['at']
        if now - last > 2 * jobs.period(d['detail'].get('schedule')) + 86400:
            out[f'clamav-stale:{host}'] = ('clamav-stale', host, f'No recent ClamAV result from {host}', 'the scan has not reported in twice its schedule; a StorageForge scan of the host reads it', 'warn')
        if run and run['signatures_at'] and now - run['signatures_at'] > SIGNATURES_OLD:
            out[f'clamav-signatures:{host}'] = ('clamav-signatures', host, f'ClamAV signatures are old on {host}', f'as of {run["version"]}', 'warn')
    return out


# ── acting on a detection ───────────────────────────────────────────
def get_detection(conn: Conn, did: int) -> dict:
    rows = conn.all('SELECT detection_id, host, path_b64, path, signature, state, quarantine_id FROM clamav_detections WHERE detection_id = :i', {'i': did})
    if not rows:
        raise LookupError(f'no detection {did}')
    return dict(zip(('id', 'host', 'b64', 'path', 'signature', 'state', 'qid'), rows[0]))


def _action_script(body: str, qid: str, b64: str, **values) -> str:
    text = ACTION_HEAD.replace('@QUAR@', QUARANTINE).replace('@QID@', shlex.quote(qid)).replace('@B64@', shlex.quote(b64))
    for k, v in values.items():
        body = body.replace(f'@{k}@', shlex.quote(str(v)))
    return _head() + text + body


def quarantine_script(d: dict, qid: str, allow_system: bool = False) -> str:
    return _action_script(QUARANTINE_BODY, qid, d['b64'], SYSTEM=1 if allow_system else 0, SIG=d['signature'])


def restore_script(d: dict) -> str:
    return _action_script(RESTORE_BODY, d['qid'], d['b64'])


def quarantine(db, conn: Conn, did: int, actor: str, allow_system: bool = False) -> dict:
    from . import deploy
    d = get_detection(conn, did)
    if d['state'] != 'open':
        raise ValueError(f'this detection is {d["state"]}')
    qid = uuid.uuid4().hex
    res = deploy.run(db, d['host'], quarantine_script(d, qid, allow_system), ['--apply'], kind='clamav-action', ref=f'quarantine:{did}', mode='apply', actor=actor, timeout=600)
    m = re.search(rf'^QUARANTINED {qid} ([0-9a-f]{{64}})$', res.get('output') or '', re.M)
    if res['status'] == 'ok' and m:
        conn.execute("""UPDATE clamav_detections SET state = 'quarantined', quarantine_id = :q, sha256 = :s, handled_by = :a, handled_at = :t
                        WHERE detection_id = :i""", {'q': qid, 's': m[1], 'a': actor, 't': int(time.time()), 'i': did})
        return {'ok': True, 'output': res['output']}
    return {'ok': False, 'output': res.get('output') or '', 'error': 'the file was not moved: see the output'}


def restore(db, conn: Conn, did: int, actor: str) -> dict:
    """Back where it was. Someone decided it is safe, so it is also ignored: the next scan would only report it again."""
    from . import deploy
    d = get_detection(conn, did)
    if d['state'] != 'quarantined' or not d['qid'] or not QID_RE.fullmatch(d['qid']):
        raise ValueError('this detection is not in quarantine')
    res = deploy.run(db, d['host'], restore_script(d), ['--apply'], kind='clamav-action', ref=f'restore:{did}', mode='apply', actor=actor, timeout=600)
    if res['status'] == 'ok' and f'RESTORED {d["qid"]}' in (res.get('output') or ''):
        conn.execute("""UPDATE clamav_detections SET state = 'open', ignored = 1, ignore_reason = 'restored from quarantine', quarantine_id = NULL,
                        handled_by = :a, handled_at = :t WHERE detection_id = :i""", {'a': actor, 't': int(time.time()), 'i': did})
        return {'ok': True, 'output': res['output']}
    return {'ok': False, 'output': res.get('output') or '', 'error': 'the file was not restored: see the output'}


def set_ignored(conn: Conn, did: int, ignored: bool, reason: str, actor: str):
    get_detection(conn, did)
    conn.execute("""UPDATE clamav_detections SET ignored = :g, ignore_reason = :r, handled_by = :a, handled_at = :t WHERE detection_id = :i""",
                 {'g': 1 if ignored else 0, 'r': reason[:500] if ignored else None, 'a': actor, 't': int(time.time()), 'i': did})


def collect(db, conn: Conn, host: str, actor: str) -> dict:
    """Read the host's last result now instead of waiting for its next scan."""
    from . import deploy
    res = deploy.run(db, host, f"set -eu\ncat {STATE}/last.tsv 2>/dev/null || echo 'no result yet'\n", kind='clamav-action', ref='collect', mode='report', actor=actor, timeout=120)
    if res['status'] != 'ok':
        return {'ok': False, 'error': 'could not read the result: see the deploy log'}
    return {'ok': True, 'new': ingest(conn, deploy.canonical(conn, host), res.get('output') or '', 'collect')}
