"""Jobs: the steps of a Moves plan, deployed to their hosts and run by systemd timers through storageforge-job.

A job runs on its destination host and pulls from its source. Deploying plan N writes, per host:
  runner  /etc/storageforge/jobs/pN-<step>.conf, .key (the job's SSH key for the source), .token (for reports),
          sf-job-pN-<step>.service/.timer (+ -<level> for rsnapshot rotations, + -verify for checksum verifies)
  source  /etc/storageforge/serve/pN-<step>.conf (allowed root, pre/post commands, snapshot) and a forced-command
          line for the job's key in storageforge-deploy's authorized_keys
Each deploy only touches its own plan's jobs (the pN- prefix), and removes the ones the plan no longer has.
Keys and tokens are made fresh on every apply and travel only inside the signed request; StorageForge keeps the
public key and the token's SHA-256.

Runs report back (POST /api/jobs/report with the job token) and leave a line in /var/lib/storageforge/jobs/<id>/
runs.jsonl, which scans read as a fallback.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import site
from . import deploy, moves, snapjobs
from .db import Conn
from .jobscript import JOB_SCRIPT
from .remote import child_env, known_hosts_name
from .runner import known_hosts_path
from .scriptkit import HELPERS, PACKAGES, longest_gap, need_line, one_line

SCHEDULED = ('mirror', 'rsnapshot', 'git')
REPORT_CA = '/etc/storageforge/report-ca.pem'       # the self-signed certificate an https report URL is checked against
LEVELS = ('hourly', 'daily', 'weekly', 'monthly')
LEVEL_CAL = {'hourly': 'hourly', 'daily': '*-*-* 02:30:00', 'weekly': 'Sun *-*-* 02:00:00', 'monthly': '*-*-01 01:30:00'}
VERIFY_CAL = {'weekly': 'Sat *-*-* 04:00:00', 'monthly': '*-*-15 04:00:00'}
DEDUPE_CAL = {'weekly': 'Sun *-*-* 05:00:00', 'monthly': '*-*-20 05:00:00'}
DAY = 86400
UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
JOB_RE = re.compile(r'[a-z0-9][a-z0-9-]{0,62}')


def job_id(plan_id: int, step_id: str) -> str:
    return f'p{int(plan_id)}-{re.sub(r"[^a-z0-9-]", "", str(step_id).lower())[:40] or "s"}'


WEEKDAYS = {'mon': 0, 'tue': 1, 'wed': 2, 'thu': 3, 'fri': 4, 'sat': 5, 'sun': 6}


def _calendar_values(text: str, low: int, high: int) -> set[int]:
    """One field of a systemd calendar time: *, 5, 1,15, 1..7 or 0/6. ValueError for anything else."""
    out = set()
    for item in text.split(','):
        item = item.split('.')[0] if '.' in item and '..' not in item else item      # seconds' fractions
        base, _, step = item.partition('/')
        lo, _, hi = base.partition('..')
        start = low if lo == '*' else int(lo)
        end = high if lo == '*' or (step and not hi) else int(hi or lo)
        out.update(range(start, end + 1, int(step) if step else 1))
    return {v for v in out if low <= v <= high}


def _calendar_weekdays(word: str) -> set[int] | None:
    """Mon, Mon,Tue or Mon..Fri as weekday numbers; None when word is not one of those (a timezone, say)."""
    out: set[int] = set()
    for item in word.lower().split(','):
        a, _, b = item.partition('..')
        if a[:3] not in WEEKDAYS or (b and b[:3] not in WEEKDAYS):
            return None
        first, last = WEEKDAYS[a[:3]], WEEKDAYS[(b or a)[:3]]
        out.update(range(first, last + 1) if first <= last else [*range(first, 7), *range(0, last + 1)])
    return out


@functools.lru_cache(maxsize=512)
def period(schedule: str | None) -> int:
    """The longest wait between runs, in seconds, from a systemd OnCalendar expression (for staleness, not for scheduling).
    A time it cannot read counts as daily: systemd is what refuses a bad one."""
    s = (schedule or 'daily').strip()
    if s in ('minutely',):
        return 60
    named = {'hourly': 3600, 'daily': DAY, 'weekly': 7 * DAY, 'monthly': 31 * DAY, 'quarterly': 92 * DAY, 'yearly': 366 * DAY}
    if s in named:
        return named[s]
    parts = s.split()
    weekdays = _calendar_weekdays(parts[0]) if parts and parts[0][0].isalpha() else None
    clock = next((p for p in reversed(parts) if ':' in p), '0:0')
    date = next((p for p in parts if '-' in p and ':' not in p), '*-*-*').split('-')
    try:
        hours, mins = clock.split(':')[:2]
        months = _calendar_values(date[-2], 1, 12)
        doms = _calendar_values(date[-1], 1, 31)
        times = [h * 60 + m for h in _calendar_values(hours, 0, 23) for m in _calendar_values(mins, 0, 59)]
    except (ValueError, IndexError):
        return DAY
    gap = longest_gap(lambda d: d.month in months and d.day in doms and (weekdays is None or d.weekday() in weekdays), times)
    return gap or DAY


# ── plan steps → job specs ──────────────────────────────────────────
def specs(conn: Conn, plan: dict) -> list[dict]:
    """Every step of a saved plan as a job, with the hosts and paths resolved from the index."""
    norm = moves.normalize(plan)
    chk = moves.check(conn, norm)
    hs = moves.hosts(conn)
    paused = {r[0] for r in conn.all('SELECT job_id FROM jobs WHERE paused = 1')}
    out = []
    for s, c in zip(norm['steps'], chk['steps']):
        sh, dh = moves.find_host(hs, s['src']['host']), moves.find_host(hs, s['dst']['host'])
        if not sh or not dh:
            raise ValueError(f'step {s["id"]}: {s["src"]["host"] if not sh else s["dst"]["host"]} has not been scanned')
        o = s['options']
        keep = [f'{lv}={o["keep"][lv]}' for lv in LEVELS if o['keep'].get(lv)]
        jid = job_id(plan['id'], s['id'])
        out.append({
            'id': jid, 'plan_id': plan['id'], 'step': s['id'], 'method': s['method'],
            'name': f'{s["method"]} {sh["name"]}:{s["src"]["path"]} -> {dh["name"]}:{s["dst"]["path"]}',
            'runner': dh['name'], 'source': sh['name'], 'local': sh['name'] == dh['name'],
            'src_host': sh['ssh_host'], 'src_port': sh['ssh_port'] or 22,
            'src': s['src']['path'], 'dst': s['dst']['path'],
            'dst_mount': (c.get('dst') or {}).get('planned_mount') or (c.get('dst') or {}).get('mount') or '/',
            'flags': ' '.join(f for f, on in (('checksum', o['checksum']), ('delete', o['delete']), ('onefs', o['one_fs']),
                                               ('link', o['link_back'])) if on),
            'excludes': s['excludes'], **({'only': s['only']} if s.get('only') else {}), 'schedule': o['schedule'] if s['method'] in SCHEDULED else None,
            'window': o['window'], 'bw_day': o['bwlimit'], 'bw_night': o['bwlimit_night'], 'night': o['night'],
            'pre': o['pre'], 'post': o['post'], 'snapshot': o['snapshot'], 'verify': o['verify'],
            'keep': ' '.join(keep), 'lowest': next((lv for lv in LEVELS if o['keep'].get(lv)), 'daily'),
            'paused': jid in paused,
            'routes': o.get('routes') or [], 'dedup': bool(o.get('dedup')), 'hash': o.get('hash') or 'sha256',
            'dedup_hardlink': bool(o.get('dedup_hardlink')), 'dedup_min_kb': o.get('dedup_min_kb') or 1024,
            'transport': o.get('transport') or 'rsync', 'preflight': bool(o.get('preflight')),
            'reserve_gb': o.get('reserve_gb', 1), 'extent_dedup': o.get('extent_dedup'),
            'hostkey': pinned_key(sh) if o.get('routes') and sh['name'] != dh['name'] else '',
        })
    return out


def pinned_key(host: dict) -> str:
    """The source's key as StorageForge pinned it, for a job that reaches it at addresses it never scanned. Empty when
    it has none yet (the job then trusts its first connection, as jobs without routes do)."""
    try:
        out = subprocess.run(['ssh-keygen', '-F', known_hosts_name(host['ssh_host'], host['ssh_port']), '-f', str(known_hosts_path())],
                             capture_output=True, text=True, timeout=10, env=child_env()).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ''
    return ''.join('storageforge-source ' + line.split(None, 1)[1] + '\n' for line in out.splitlines()
                   if line and not line.startswith('#') and len(line.split()) >= 3)


def report_ca(report_url: str | None) -> str | None:
    """For an https report URL: the certificate StorageForge is served with (STORAGEFORGE_REPORT_CA_FILE), which hosts
    then trust for reports and nothing else. None when there is no such file: hosts use their system CAs."""
    path = os.environ.get('STORAGEFORGE_REPORT_CA_FILE')
    if not (report_url or '').startswith('https://') or not path:
        return None
    try:
        pem = open(path).read().strip()
    except OSError:
        return None
    return pem + '\n' if pem.startswith('-----BEGIN CERTIFICATE-----') else None


def _unit_escape(s: str) -> str:
    return s.replace('%', '%%').replace('\n', ' ')


def conf_text(spec: dict, report_url: str | None) -> str:
    q = shlex.quote
    v = {'ID': spec['id'], 'NAME': spec['name'], 'METHOD': spec['method'], 'SRC_LOCAL': '1' if spec['local'] else '0',
         'SRC_HOST': spec['src_host'], 'SRC_PORT': str(spec['src_port']), 'SRC': spec['src'], 'DST': spec['dst'],
         'DST_MOUNT': spec['dst_mount'], 'FLAGS': spec['flags'], 'KEEP': spec['keep'], 'LOWEST': spec['lowest'],
         'WINDOW': spec['window'] or '', 'BW_DAY': str(spec['bw_day'] or ''), 'BW_NIGHT': str(spec['bw_night'] or ''),
         'NIGHT': spec['night'] or '', 'SNAP': '1' if spec['snapshot'] else '0',
         'HOOKS': '1' if spec['pre'] or spec['post'] else '0', 'REPORT_URL': (report_url or '').rstrip('/'),
         'DEDUP': '1' if spec.get('dedup') else '0', 'DEDUP_HARDLINK': '1' if spec.get('dedup_hardlink') else '0',
         'DEDUP_MIN': str((spec.get('dedup_min_kb') or 1024) * 1024), 'HASH': spec.get('hash') or 'sha256',
         'TRANSPORT': spec.get('transport') or 'rsync', 'PREFLIGHT': '1' if spec.get('preflight') else '0',
         'RESERVE_GB': str(spec.get('reserve_gb', 1))}
    routes = [f'{r["via"]}|{r["address"]}|{r["iface"] or ""}' for r in spec.get('routes') or []] if not spec['local'] else []
    return ('# StorageForge job: written by deploys, replaced by the next one\n'
            + ''.join(f'{k}={q(val)}\n' for k, val in v.items())
            + 'EXCLUDES=(' + ' '.join(q(x) for x in spec['excludes']) + ')\n'
            + ('ONLY=(' + ' '.join(q(x) for x in moves.only_filters(spec['only'])) + ')\n' if spec.get('only') else '')
            + 'ROUTES=(' + ' '.join(q(x) for x in routes) + ')\n')


def serve_text(spec: dict) -> str:
    q = shlex.quote
    return ('# StorageForge: what job ' + spec['id'] + ' may read and run here (its key\'s forced command)\n'
            f'ROOT={q(spec["src"])}\nSNAP={1 if spec["snapshot"] else 0}\n'
            f'DEDUP={1 if spec.get("dedup") else 0}\nHASH={q(spec.get("hash") or "sha256")}\n'
            f'STREAM={q("" if (spec.get("transport") or "rsync") == "rsync" else spec["transport"])}\n'
            f'PRE=({" ".join(q(c) for c in spec["pre"])})\nPOST=({" ".join(q(c) for c in spec["post"])})\n')


def units(spec: dict) -> tuple[dict, list[str]]:
    """{unit file name: content}, and the timers to enable."""
    jid, desc = spec['id'], _unit_escape(spec['name'])
    mounts = f'RequiresMountsFor={_unit_escape(spec["dst_mount"])}\n' if spec['dst_mount'] != '/' else ''

    def service(suffix, what, cmd):
        return (f'[Unit]\nDescription=StorageForge job {jid}{suffix}: {what}\nAfter=network-online.target\n'
                f'Wants=network-online.target\n{mounts}\n[Service]\nType=oneshot\nNice=10\nIOSchedulingClass=idle\n'
                f'ExecStart={deploy.JOBBIN} {cmd}\n')

    def timer(suffix, cal):
        return (f'[Unit]\nDescription=StorageForge job {jid}{suffix} timer\n\n[Timer]\nOnCalendar={cal}\nPersistent=true\n'
                f'RandomizedDelaySec=5min\n\n[Install]\nWantedBy=timers.target\n')

    files, timers = {}, []
    base = f'sf-job-{jid}'
    if spec['method'] == 'rsnapshot':
        low = spec['lowest']
        files[f'{base}.service'] = service('', desc, f'run {jid} {low}')
        cal = LEVEL_CAL[low] if spec['schedule'] in LEVELS else spec['schedule']
        files[f'{base}.timer'] = timer('', cal)
        timers.append(f'{base}.timer')
        for kv in spec['keep'].split():
            lv = kv.split('=')[0]
            if lv != low:
                files[f'{base}-{lv}.service'] = service(f' ({lv})', f'rotate {lv} snapshots', f'run {jid} {lv}')
                files[f'{base}-{lv}.timer'] = timer(f' ({lv})', LEVEL_CAL[lv])
                timers.append(f'{base}-{lv}.timer')
    else:
        files[f'{base}.service'] = service('', desc, f'run {jid}')
        if spec['method'] in SCHEDULED:
            files[f'{base}.timer'] = timer('', spec['schedule'])
            timers.append(f'{base}.timer')
    if spec['method'] != 'git':
        files[f'{base}-verify.service'] = service(' verify', f'checksum verify of {desc}', f'verify {jid}')
        if spec['verify']:
            files[f'{base}-verify.timer'] = timer(' verify', VERIFY_CAL[spec['verify']])
            timers.append(f'{base}-verify.timer')
    if spec.get('extent_dedup'):
        files[f'{base}-dedupe.service'] = service(' dedupe', f'duperemove over {_unit_escape(spec["dst"])}', f'dedupe {jid}')
        files[f'{base}-dedupe.timer'] = timer(' dedupe', DEDUPE_CAL[spec['extent_dedup']])
        timers.append(f'{base}-dedupe.timer')
    return files, timers


# ── the deploy script for one host ──────────────────────────────────
HOST_HEAD = r"""#!/usr/bin/env bash
# StorageForge jobs of plan "{name}" on {host}: generated {date}. Report by default, --apply to make it so.
set -uo pipefail
APPLY=0; [[ ${{1:-}} == --apply ]] && APPLY=1
PREFIX={prefix}
"""

HOST_FUNCS = HELPERS + r"""
ETC=/etc/storageforge UNITS=/etc/systemd/system MANAGED=/var/lib/storageforge/managed SELF_BIN=/usr/local/sbin/storageforge-job
WANT=()
want_file() { # path mode, content on stdin -> ok | would write | written
  local p=$1 mode=$2 tmp; tmp=$(mktemp); cat >"$tmp"; WANT+=("$p")
  if [[ -f $p ]] && cmp -s "$tmp" "$p"; then ok "$p"; rm -f "$tmp"; return 0; fi
  if ((APPLY)); then install -D -o root -g root -m "$mode" "$tmp" "$p" && doing "wrote $p" || conflict "could not write $p"
  else
    missing "$( [[ -e $p ]] && echo 'would update' || echo 'would write') $p"
    if [[ -e $p && $p != "$SELF_BIN" ]] && command -v diff >/dev/null; then diff -u "$p" "$tmp" | sed -n '3,40p' | sed 's/^/            /'; fi
  fi
  rm -f "$tmp"
}
secret_file() { # path, content on stdin (apply only)
  local p=$1 tmp; tmp=$(mktemp); cat >"$tmp"; WANT+=("$p")
  install -D -o root -g root -m 0600 "$tmp" "$p" && doing "wrote $p (secret)"; rm -f "$tmp"
}
need() { command -v "$1" >/dev/null 2>&1 && ok "$1: $(command -v "$1")" || conflict "$1 is not installed ($2)"; }
""" + PACKAGES

HOST_TAIL = r"""
section "stale jobs of this plan"
stale=0
for f in "$ETC"/jobs/"$PREFIX"*.conf "$ETC"/serve/"$PREFIX"*.conf "$UNITS"/sf-job-"$PREFIX"*.service "$UNITS"/sf-job-"$PREFIX"*.timer; do
  [[ -e $f ]] || continue
  printf '%s\n' "${WANT[@]}" | grep -Fx -- "$f" >/dev/null && continue
  stale=1
  if ((APPLY)); then
    [[ $f == *.timer ]] && systemctl disable --now "$(basename "$f")" >/dev/null 2>&1
    # a removed job's stream snapshots would pin their disk space on the source for good
    [[ $f == "$ETC"/serve/*.conf && -x $SELF_BIN ]] && grep -q '^STREAM=[a-z]' "$f" && "$SELF_BIN" --serve "$(basename "$f" .conf)" stream-clean >/dev/null 2>&1
    rm -f -- "$f"; [[ $f == *.conf && $f == "$ETC"/jobs/* ]] && rm -f -- "${f%.conf}.key" "${f%.conf}.token" "${f%.conf}.hostkey"
    [[ $f == *.conf ]] && rm -f -- "/var/lib/storageforge/index/$(basename "$f" .conf)".*
    doing "removed $f"
  else missing "would remove $f"; fi
done
((stale)) || ok "nothing to remove"
if ((APPLY)) && [[ -n $KEYLINES_SET ]]; then
  section "job keys allowed in (storageforge-deploy's authorized_keys)"
  keys=/var/lib/storageforge/deploy/.ssh/authorized_keys
  if [[ -f $keys ]]; then
    { grep -v -- "storageforge-job --serve $PREFIX" "$keys" || true; [[ -n $KEYLINES ]] && printf '%s\n' "$KEYLINES"; } >"$keys.new"
    chown root:root "$keys.new"; chmod 0644 "$keys.new"; mv "$keys.new" "$keys"
    ok "$(printf '%s' "$KEYLINES" | grep -c . || true) job key(s) for this plan"
  else conflict "$keys is missing: set up deploy access on this host again"; fi
fi
if command -v systemctl >/dev/null; then
  section "timers"
  ((APPLY)) && systemctl daemon-reload
  for t in "${TIMERS[@]}"; do
    if ((APPLY)); then systemctl enable --now "$t" >/dev/null 2>&1 && ok "$t enabled" || conflict "could not enable $t"
    else [[ $(systemctl is-enabled "$t" 2>/dev/null) == enabled ]] && ok "$t enabled" || missing "would enable $t"; fi
  done
  for t in "${PAUSED[@]}"; do
    ((APPLY)) && systemctl disable --now "$t" >/dev/null 2>&1; info "$t paused"
  done
  for t in "${TIMERS[@]}" "${PAUSED[@]}"; do
    systemd-analyze calendar "$(sed -n 's/^OnCalendar=//p' "$UNITS/$t" 2>/dev/null || true)" >/dev/null 2>&1 || [[ ! -e $UNITS/$t ]] || conflict "$t: systemd does not understand its OnCalendar time"
  done
fi
if ((APPLY)); then
  mkdir -p "$MANAGED"; chmod 0755 "$MANAGED"
  sums=(); for f in "${WANT[@]}"; do [[ -r $f && $(stat -c %a "$f") != 600 ]] && sums+=("$f"); done
  if ((${#sums[@]})); then sha256sum "${sums[@]}" >"$MANAGED/jobs-$PREFIX.sha256"; else rm -f "$MANAGED/jobs-$PREFIX.sha256"; fi
  chmod 0644 "$MANAGED/jobs-$PREFIX.sha256" 2>/dev/null
fi
echo
if ((PROBLEMS)); then echo "$PROBLEMS problem(s)"; exit 1; fi
echo "done"
"""


def _heredoc(cmd: str, body: str) -> str:
    tag = 'SF_' + secrets.token_hex(6).upper()
    if tag in body:
        tag += 'X'
    return f"{cmd} <<'{tag}'\n{body}{'' if body.endswith(chr(10)) else chr(10)}{tag}\n"


def host_script(plan: dict, host: str, runner_specs: list[dict], source_specs: list[dict], report_url: str | None,
                secrets_: dict | None = None) -> str:
    """The deploy script for one host and one plan. secrets_ (apply only): {job id: {'key': private, 'pub': public,
    'token': token}}."""
    q = shlex.quote
    prefix = f'p{int(plan["id"])}-'
    parts = [HOST_HEAD.format(name=one_line(plan['name']), host=one_line(host), date=time.strftime('%Y-%m-%d %H:%M'),
                              prefix=q(prefix)), HOST_FUNCS]
    methods = {s['method'] for s in runner_specs}
    parts.append('section "tools"\n')
    if runner_specs:
        parts.append('need systemctl "systemd runs the timers"\n')
        if methods & {'copy', 'move', 'mirror', 'rsnapshot'}:
            parts.append(need_line('rsync'))
        if 'rsnapshot' in methods:
            parts.append(need_line('rsnapshot'))
        if 'git' in methods:
            parts.append(need_line('git'))
        if any(s.get('dedup') for s in runner_specs):
            parts.append(need_line('python3'))
        if any(s.get('hash') == 'blake3' and s.get('dedup') for s in runner_specs + source_specs):
            parts.append('need b3sum "blake3 hashes"\n')
        if any(s.get('extent_dedup') for s in runner_specs):
            parts.append(need_line('duperemove'))
        if any(s.get('transport') == 'btrfs' for s in runner_specs):
            parts.append(need_line('btrfs-progs'))
        if any(s.get('transport') == 'zfs' for s in runner_specs):
            parts.append('need zfs "ZFS snapshot streams"\n')
        if any(r.get('iface') for s in runner_specs for r in s.get('routes') or []):
            parts.append('ssh -G -o BindInterface=lo localhost >/dev/null 2>&1 && ok "ssh can bind to an interface" '
                         '|| conflict "this OpenSSH has no BindInterface: update it, or leave the interface out of the routes"\n')
        if report_url:
            parts.append(f'cacert=(); [[ -r {REPORT_CA} ]] && cacert=(--cacert {REPORT_CA})\n'
                         f'code=$(curl -s -m 5 ${{cacert[@]+"${{cacert[@]}}"}} -o /dev/null -w "%{{http_code}}" {q(report_url.rstrip("/") + "/healthz")} 2>/dev/null || true)\n'
                         f'[[ $code == 200 ]] && ok {q("reports reach " + report_url)} || info {q("cannot reach " + report_url)}'
                         f'" from here (HTTP ${{code:-none}}): runs are still picked up by scans"\n')
        else:
            parts.append('info "no report URL set in StorageForge: runs are picked up by scans only"\n')
    if any(s['snapshot'] or s.get('transport') == 'btrfs' for s in source_specs):
        parts.append(need_line('btrfs-progs'))
    if any(s.get('transport') == 'zfs' for s in source_specs):
        parts.append('need zfs "ZFS snapshot streams"\n')
    if any(s.get('dedup') for s in source_specs):
        parts.append(need_line('python3'))
    remote_sources = [s for s in source_specs if not s['local']]
    if any(s['method'] != 'git' for s in remote_sources):
        parts.append(need_line('rsync'))
    if any(s['method'] == 'git' for s in remote_sources):
        parts.append(need_line('git'))
    if runner_specs or source_specs:
        parts.append('section "storageforge-job"\n' + _heredoc(f'want_file {deploy.JOBBIN} 0755', JOB_SCRIPT))
        ca = report_ca(report_url) if runner_specs else None
        if ca:          # public: lets reports check StorageForge's self-signed certificate
            parts.append(_heredoc(f'want_file {REPORT_CA} 0644', ca))
    timers, paused = [], []
    for s in runner_specs:
        parts.append(f'section {q("job " + s["id"] + ": " + s["name"])}\n')
        # values only ever as quoted words: inside "..." a $(...) in a scanned or designed path would run as root
        parts.append(f'[[ {q(s["dst_mount"])} == / ]] || mountpoint -q {q(s["dst_mount"])} && ok {q("destination mount " + s["dst_mount"])} '
                     f'|| info {q(s["dst_mount"] + " is not mounted now: runs wait for it")}\n')
        parts.append(_heredoc(f'want_file {q("/etc/storageforge/jobs/" + s["id"] + ".conf")} 0644', conf_text(s, report_url)))
        if s.get('hostkey'):
            parts.append(_heredoc(f'want_file {q("/etc/storageforge/jobs/" + s["id"] + ".hostkey")} 0644', s['hostkey']))
        for r in s.get('routes') or []:
            if r['iface'] and not s['local']:
                parts.append(f'[[ -e {q("/sys/class/net/" + r["iface"])} ]] && ok {q("interface " + r["iface"])} '
                             f'|| info {q("no interface " + r["iface"] + " now: the " + r["via"] + " route is skipped until it is up")}\n')
        files, ts = units(s)
        for name, body in files.items():
            parts.append(_heredoc(f'want_file {q("/etc/systemd/system/" + name)} 0644', body))
        (paused if s['paused'] else timers).extend(ts)
        if secrets_:
            sec = secrets_[s['id']]
            parts.append(_heredoc(f'secret_file {q("/etc/storageforge/jobs/" + s["id"] + ".token")}', sec['token'] + '\n'))
            if not s['local']:
                parts.append(_heredoc(f'secret_file {q("/etc/storageforge/jobs/" + s["id"] + ".key")}', sec['key']))
        else:
            parts.append(f'[[ -e /etc/storageforge/jobs/{s["id"]}.token ]] && ok "job token present (apply makes a new one)" '
                         f'|| missing "would write the job token{"" if s["local"] else " and SSH key"}"\n')
    keylines = []
    for s in source_specs:
        parts.append(f'section {q("serves job " + s["id"] + " (" + s["runner"] + " pulls " + s["src"] + ")")}\n')
        parts.append(f'[[ -d {q(s["src"])} ]] && ok {q("source " + s["src"])} || conflict {q("source " + s["src"] + " does not exist")}\n')
        if s['snapshot']:      # a btrfs snapshot stops at subvolume boundaries: what is below one is not in it
            parts.append(f'nested=$(btrfs subvolume list -o {q(s["src"])} 2>/dev/null | grep -c . || true)\n'
                         f'((nested)) && info "$nested"{q(" subvolume(s) below " + s["src"] + " are not in its snapshot: add a step for each")}\n')
        parts.append(_heredoc(f'want_file {q("/etc/storageforge/serve/" + s["id"] + ".conf")} 0644', serve_text(s)))
        if s['pre'] or s['post']:
            parts.append(f'info {q("runs before: " + "; ".join(s["pre"]) + "  after: " + "; ".join(s["post"]))}\n')
        if not s['local'] and secrets_:
            pub = secrets_[s['id']]['pub']
            keylines.append(f'restrict,command="sudo -n {deploy.JOBBIN} --serve {s["id"]} \\"$SSH_ORIGINAL_COMMAND\\"" {pub} '
                            f'storageforge:job:{s["id"]}\n')
    parts.append(f'TIMERS=({" ".join(q(t) for t in timers)})\nPAUSED=({" ".join(q(t) for t in paused)})\n')
    parts.append(_heredoc('KEYLINES=$(cat', ''.join(keylines)) + ')\n' if keylines else "KEYLINES=''\n")
    parts.append(f'KEYLINES_SET={"1" if secrets_ is not None else ""}\n')
    parts.append(HOST_TAIL)
    return ''.join(parts)


def plan_hash(plan: dict) -> str:
    """A fingerprint of a plan's steps: a deployment whose hash differs has changes not deployed yet."""
    return hashlib.sha256(json.dumps(moves.normalize(plan)['steps'], sort_keys=True).encode()).hexdigest()[:16]


def new_secrets(specs_: list[dict]) -> dict:
    out = {}
    for s in specs_:
        k = ed25519.Ed25519PrivateKey.generate()
        out[s['id']] = {
            'token': secrets.token_urlsafe(32),
            'key': k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                   serialization.NoEncryption()).decode(),
            'pub': k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode(),
        }
    return out


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def deploy_items(db, conn: Conn, plan: dict, mode: str, report_url: str | None, actor: str, paused: bool = False) -> list[dict]:
    """deploy.start_group items for one plan: every host that serves, runs or used to run its jobs. paused: install
    with every timer off, so jobs can be dry-run on the real hosts before they run for real."""
    sp = specs(conn, plan) if plan.get('steps') else []
    if paused:
        for s in sp:
            s['paused'] = True
    ref = f'p{int(plan["id"])}'
    before = {d['host'] for d in deploy.deployed(conn, kind='jobs') if d['ref'] == ref}
    runners = {s['runner'] for s in sp}
    sources = {s['source'] for s in sp}
    order = sorted(sources) + sorted(runners - sources) + sorted(before - sources - runners)
    phase = {h: 0 if h in sources else 1 for h in order}    # a source's serve config and keys go first: runners test them
    sec = new_secrets(sp) if mode == 'apply' else None     # {} for a plan with no steps left: apply still cleans up
    if sec is not None:      # store before the hosts get them: a run may report the moment its timer fires
        now = int(time.time())
        for s in sp:
            row = {'id': s['id'], 'p': plan['id'], 'st': s['step'], 'n': s['name'], 'm': s['method'], 'r': s['runner'],
                   'src': s['source'], 'sch': s['schedule'], 'spec': json.dumps({**s, 'pub': sec[s['id']]['pub']}),
                   'tok': token_hash(sec[s['id']]['token']), 't': now}
            conn.execute('DELETE FROM jobs WHERE job_id = :id', row)
            conn.execute("""INSERT INTO jobs (job_id, plan_id, step_id, name, method, runner_host, source_host, schedule,
                                              spec_json, token_hash, paused, deployed_at)
                            VALUES (:id, :p, :st, :n, :m, :r, :src, :sch, :spec, :tok, :pz, :t)""",
                         {**row, 'pz': 1 if s['paused'] else 0})
        gone = [r[0] for r in conn.all('SELECT job_id FROM jobs WHERE plan_id = :p AND removed_at IS NULL', {'p': plan['id']})
                if r[0] not in sec]
        for jid in gone:
            conn.execute('UPDATE jobs SET removed_at = :t WHERE job_id = :j', {'t': now, 'j': jid})
    items = []
    for h in order:
        script = site.stamp(conn, host_script(plan, h, [s for s in sp if s['runner'] == h], [s for s in sp if s['source'] == h],
                                              report_url, sec))

        def done(res, h=h):
            c = db.connect()
            try:
                deploy.mark_deployed(c, h, 'jobs', ref, plan_hash(plan),
                                     {'jobs': [s['id'] for s in sp if h in (s['runner'], s['source'])], 'hosts': order}, actor)
            finally:
                c.close()
        items.append({'host': h, 'script': script, 'args': ['--apply'] if mode == 'apply' else [], 'kind': 'jobs', 'ref': ref,
                      'mode': mode, 'phase': phase[h], **({'on_ok': done} if mode == 'apply' else {})})
    if mode == 'apply':
        for h in sorted(runners):
            remote = [s['id'] for s in sp if s['runner'] == h and not s['local']]
            if remote:
                items.append({'host': h, 'kind': 'job-test', 'ref': ref, 'mode': 'apply', 'phase': 2,
                              'script': ''.join(f'{deploy.JOBBIN} test {j} || rc=1\n' for j in remote) + 'exit ${rc:-0}\n'})
    return items


# ── actions on one deployed job ─────────────────────────────────────
ACTIONS = {
    'run': lambda j: f'systemctl start --no-block sf-job-{j}.service && echo "started sf-job-{j}.service"',
    'dryrun': lambda j: f'exec {deploy.JOBBIN} dryrun {j}',
    'verify': lambda j: f'systemctl start --no-block sf-job-{j}-verify.service && echo "started the checksum verify"',
    'pause': lambda j: f'for t in /etc/systemd/system/sf-job-{j}.timer /etc/systemd/system/sf-job-{j}-*.timer; do '
                       f'[ -e "$t" ] && systemctl disable --now "$(basename "$t")" && echo "paused $(basename "$t")"; done; true',
    'resume': lambda j: f'for t in /etc/systemd/system/sf-job-{j}.timer /etc/systemd/system/sf-job-{j}-*.timer; do '
                        f'[ -e "$t" ] && systemctl enable --now "$(basename "$t")" && echo "resumed $(basename "$t")"; done; true',
    'cutover': lambda j: f'exec {deploy.JOBBIN} cutover {j}',
    'log': lambda j: f'journalctl -u "sf-job-{j}*" -n 300 --no-pager -o short-iso 2>&1 || true',
    'snapshots': lambda j: f'exec {deploy.JOBBIN} snapshots {j}',
    'dedupe': lambda j: f'systemctl start --no-block sf-job-{j}-dedupe.service && echo "started duperemove"',
}


def get(conn: Conn, jid: str) -> dict:
    if not JOB_RE.fullmatch(jid or ''):
        raise ValueError('bad job id')
    rows = conn.all("""SELECT job_id, plan_id, step_id, name, method, runner_host, source_host, schedule, spec_json, paused,
                              deployed_at, removed_at FROM jobs WHERE job_id = :j""", {'j': jid})
    if not rows:
        raise LookupError(f'no deployed job {jid}')
    r = rows[0]
    return {'id': r[0], 'plan_id': r[1], 'step': r[2], 'name': r[3], 'method': r[4], 'runner': r[5], 'source': r[6],
            'schedule': r[7], 'spec': json.loads(r[8] or '{}'), 'paused': bool(r[9]), 'deployed_at': r[10], 'removed_at': r[11]}


def action(db, conn: Conn, jid: str, verb: str, actor: str) -> dict:
    j = get(conn, jid)
    if snapjobs.is_imported(j):
        return snapjobs.action(db, conn, j, verb, actor)
    if verb not in ACTIONS:
        raise ValueError(f'unknown action {verb}')
    if verb == 'cutover' and j['method'] != 'move':
        raise ValueError('only move jobs cut over')
    if verb == 'dedupe' and not j['spec'].get('extent_dedup'):
        raise ValueError('this job has no extent dedup')
    res = deploy.run(db, j['runner'], ACTIONS[verb](jid), kind='job-action', ref=f'{jid}:{verb}', mode='apply',
                     actor=actor, timeout=600)
    if verb in ('pause', 'resume') and res['status'] == 'ok':
        conn.execute('UPDATE jobs SET paused = :p WHERE job_id = :j', {'p': 1 if verb == 'pause' else 0, 'j': jid})
    if verb == 'snapshots' and res['status'] == 'ok':
        res['snapshots'] = sorted((json.loads(l) for l in res['output'].splitlines() if l.startswith('{')),
                                  key=lambda s: -s['time'])
    return res


def browse(db, conn: Conn, jid: str, snapshot: str, rel: str, actor: str) -> dict:
    j = get(conn, jid)
    if snapjobs.is_imported(j):
        return snapjobs.browse(db, conn, j, snapshot, rel, actor)
    _snap_args(snapshot, rel)
    res = deploy.run(db, j['runner'], f'exec {deploy.JOBBIN} ls {jid} {shlex.quote(snapshot)} {shlex.quote(rel)}',
                     kind='job-action', ref=f'{jid}:ls', mode='apply', actor=actor, timeout=120)
    entries = []
    for line in res['output'].splitlines():
        parts = line.split('\t')
        if len(parts) == 4 and parts[0] in ('d', 'f', 'l'):
            entries.append({'type': parts[0], 'size': int(parts[1] or 0), 'mtime': int(float(parts[2] or 0)), 'name': parts[3]})
    return {'job': jid, 'snapshot': snapshot, 'path': rel, 'entries': entries,
            'error': None if res['status'] == 'ok' else res['output'][-500:]}


def _snap_args(snapshot: str, rel: str):
    if not re.fullmatch(r'[a-z]+\.\d+', snapshot or ''):
        raise ValueError('bad snapshot name')
    if '..' in (rel or '') or (rel or '').startswith('/') or '\n' in (rel or ''):
        raise ValueError('bad path')


def restore_target(conn: Conn, jid: str, snapshot: str, rel: str) -> tuple[dict, str, str]:
    """Checks a restore request: (job, target, parent folder). The target is new: <original>.restored-<time>."""
    j = get(conn, jid)
    if snapjobs.is_imported(j):
        return (j, *snapjobs.restore_target(j, snapshot, rel))
    _snap_args(snapshot, rel)
    if not rel:
        raise ValueError('pick a file or folder to restore')
    src = j['spec'].get('src') or ''
    parent = (src.rstrip('/') + '/' + rel).rsplit('/', 1)[0]
    return j, f'{src.rstrip("/")}/{rel}.restored-{time.strftime("%Y%m%d-%H%M%S")}', parent


def restore(db, conn: Conn, jid: str, snapshot: str, rel: str, actor: str, gid: str | None = None,
            target: str | None = None) -> dict:
    """Copy rel from a snapshot back to the source host, beside the original: <original>.restored-<time>/<name>."""
    j, made, parent = restore_target(conn, jid, snapshot, rel)
    target = target or made
    if snapjobs.is_imported(j):
        return {**snapjobs.restore(db, j, snapshot, rel, target, actor, gid), 'parent': parent}
    q = shlex.quote
    pack = f'exec {deploy.JOBBIN} pack {jid} {q(snapshot)} {q(rel)}'
    unpack = f'exec {deploy.JOBBIN} unpack {jid} {q(target)}'
    gid = gid or uuid.uuid4().hex
    if j['runner'] == j['source']:
        # pack's stderr starts with the size (for the UI's progress), then holds why it failed, if it did
        res = deploy.run(db, j['runner'], f'set -o pipefail\ne=$(mktemp); trap \'rm -f "$e"\' EXIT\n'
                                          f'{deploy.JOBBIN} pack {jid} {q(snapshot)} {q(rel)} 2>"$e" | '
                                          f'{deploy.JOBBIN} unpack {jid} {q(target)}; rc=$?\n'
                                          'if ((rc)); then sed \'1{/^[0-9]*$/d}\' "$e" >&2; fi; exit $rc',
                         kind='restore', ref=jid, mode='apply', actor=actor, group_id=gid, timeout=6 * 3600)
    else:
        with deploy.raw(db, j['runner'], pack, kind='restore-pack', ref=jid, actor=actor, group_id=gid) as p:
            res = deploy.run(db, j['source'], unpack, kind='restore', ref=jid, mode='apply', actor=actor, group_id=gid,
                             data=iter(lambda: p.stdout.read(1 << 16), b''), timeout=6 * 3600)
        if p.returncode:     # the runner could not pack it: say why, not just that the source got no archive
            why = '\n'.join(l for l in b''.join(p.errors).decode('utf-8', 'replace').splitlines() if not l.isdigit())
            res = {**res, 'status': 'failed', 'output': f'{res.get("output") or ""}\non {j["runner"]}: {why}'.strip()}
    return {**res, 'target': target, 'parent': parent, 'note': 'on an SELinux host, run restorecon -R on the restored folder: copies carry no labels'}


# ── run reports and history ─────────────────────────────────────────
def job_for_token(conn: Conn, token: str) -> str | None:
    if not token or len(token) > 200:
        return None
    return conn.scalar('SELECT job_id FROM jobs WHERE token_hash = :h AND removed_at IS NULL', {'h': token_hash(token)})


def ingest(conn: Conn, r: dict, via: str) -> bool:
    """One run line from storageforge-job. Returns False for a duplicate."""
    run_uuid, jid = str(r.get('run') or ''), str(r.get('job') or '')
    if not UUID_RE.fullmatch(run_uuid) or not JOB_RE.fullmatch(jid):
        raise ValueError('bad run report')
    if conn.scalar('SELECT count(*) FROM job_runs WHERE run_uuid = :u', {'u': run_uuid}):
        return False

    def num(k):
        try:
            return int(r.get(k) or 0)
        except (TypeError, ValueError):
            return 0
    if max(num('start'), num('end')) > time.time() + 600:      # a forged "ok" dated ahead would hide real failures
        raise ValueError('run times are in the future')
    conn.execute("""INSERT INTO job_runs (run_uuid, job_id, kind, level, started_at, finished_at, exit_code, bytes, files,
                                          message, via, received_at)
                    VALUES (:u, :j, :k, :l, :s, :e, :rc, :b, :f, :m, :v, :t)""",
                 {'u': run_uuid, 'j': jid, 'k': str(r.get('kind') or 'run')[:20], 'l': str(r.get('level') or '')[:20] or None,
                  's': num('start'), 'e': num('end') or None, 'rc': num('rc'), 'b': num('bytes'), 'f': num('files'),
                  'm': str(r.get('message') or '')[:2000], 'v': via, 't': int(time.time())})
    return True


def ingest_state(conn: Conn, r: dict) -> None:
    """A running job's latest state event: one row per job, replaced each time. Advisory: runs are what count."""
    jid, run_uuid = str(r.get('job') or ''), str(r.get('run') or '')
    if not JOB_RE.fullmatch(jid) or not UUID_RE.fullmatch(run_uuid):
        raise ValueError('bad state event')
    try:
        pct = None if r.get('percent') is None else max(0, min(int(r['percent']), 100))
        ratio = max(0.0, min(float(r.get('dedup_ratio') or 0), 1.0))
        at = int(r.get('at') or 0)
    except (TypeError, ValueError):
        raise ValueError('bad state event') from None
    if at > time.time() + 600:
        raise ValueError('state time is in the future')
    row = {'j': jid, 'u': run_uuid, 's': str(r.get('state') or '')[:20], 'p': pct, 'sp': str(r.get('speed') or '')[:20], 'd': ratio,
           'rt': str(r.get('route') or '')[:10], 'n': str(r.get('node') or '')[:255], 'a': at, 't': int(time.time())}
    conn.execute('DELETE FROM job_state WHERE job_id = :j', row)
    conn.execute("""INSERT INTO job_state (job_id, run_uuid, state, percent, speed, dedup_ratio, route, node, at, received_at)
                    VALUES (:j, :u, :s, :p, :sp, :d, :rt, :n, :a, :t)""", row)


def ingest_scan(conn: Conn, host: str, text: str) -> int:
    """Run lines a scan read from /var/lib/storageforge/jobs/*/runs.jsonl: the fallback when reports could not post."""
    mine = {r[0] for r in conn.all('SELECT job_id FROM jobs WHERE lower(runner_host) = lower(:h)', {'h': host})}
    n = 0
    for line in (text or '').splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and r.get('job') in mine:
            try:
                n += ingest(conn, r, 'scan')
            except ValueError:
                pass
    return n


def runs(conn: Conn, jid: str, limit: int = 50) -> list[dict]:
    rows = conn.all("""SELECT run_uuid, kind, level, started_at, finished_at, exit_code, bytes, files, message, via
                       FROM job_runs WHERE job_id = :j ORDER BY started_at DESC LIMIT :l""", {'j': jid, 'l': limit})
    return [dict(zip(('run', 'kind', 'level', 'start', 'end', 'rc', 'bytes', 'files', 'message', 'via'), r)) for r in rows]


def good(r: dict) -> bool:
    return r['rc'] == 0 and r['kind'] == 'run' and not str(r.get('message') or '').startswith('skipped')


def overview(conn: Conn, now: float | None = None) -> list[dict]:
    """Every deployed job with its last runs and a state: ok, failed, stale, never-ran, paused, removed."""
    now = now or time.time()
    out = []
    live = {r[0]: {'state': r[1], 'percent': r[2], 'speed': r[3], 'dedup_ratio': r[4], 'route': r[5], 'node': r[6], 'at': r[7]}
            for r in conn.all('SELECT job_id, state, percent, speed, dedup_ratio, route, node, at FROM job_state')}
    for r in conn.all("""SELECT job_id, plan_id, name, method, runner_host, source_host, schedule, paused, deployed_at,
                                spec_json FROM jobs WHERE removed_at IS NULL ORDER BY plan_id, job_id"""):
        jid, plan_id, name, method, runner, source, schedule, paused, deployed_at, spec = r
        recent = runs(conn, jid, 30)
        last = next((x for x in recent if x['kind'] == 'run' and not str(x['message'] or '').startswith('skipped')), None)
        ok = next((x for x in recent if good(x)), None)
        verify = next((x for x in recent if x['kind'] == 'verify'), None)
        s = json.loads(spec or '{}')
        imported = bool(s.get('imported'))      # no schedule found for it means nobody can say it is late
        per = (period(schedule) if schedule else None) if imported else (period(schedule) if method in SCHEDULED else None)
        if s.get('missing'):
            state = 'missing'
        elif paused:
            state = 'paused'
        elif last is None and imported:
            state = 'unseen'
        elif last is None:
            state = 'never-ran' if not per or now - (deployed_at or now) < 2 * per + 3600 else 'stale'
        elif last['rc'] not in (0, 124):
            state = 'failed'
        elif per and now - ((ok or {}).get('end') or (ok or {}).get('start') or deployed_at or 0) > 2 * per + 3600:
            state = 'stale'
        else:
            state = 'ok'
        out.append({'id': jid, 'plan_id': plan_id, 'name': name, 'method': method, 'runner': runner, 'source': source,
                    'schedule': schedule, 'paused': bool(paused), 'deployed_at': deployed_at, 'state': state,
                    'last': last, 'last_ok': ok, 'verify': verify, 'period': per, 'src': s.get('src'), 'dst': s.get('dst'),
                    'snapshots': method in ('rsnapshot', 'snapper'), 'window': s.get('window'), 'verify_schedule': s.get('verify'),
                    'pre': s.get('pre') or [], 'post': s.get('post') or [], 'snapshot': s.get('snapshot'),
                    'live': live.get(jid), 'routes': s.get('routes') or [], 'dedup': bool(s.get('dedup')),
                    'transport': s.get('transport') or 'rsync', 'extent_dedup': s.get('extent_dedup'),
                    'imported': imported, 'sources': [p.rstrip('/') or '/' for p in s.get('sources') or ([s['src']] if s.get('src') else [])], 'config': s.get('config'), 'levels': s.get('levels'),
                    'fstype': s.get('fstype'), 'mount': s.get('mount'), 'fit': s.get('fit') or [], 'count': s.get('count')})
    return out
