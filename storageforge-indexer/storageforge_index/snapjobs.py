"""Importing and managing rsnapshot and snapper jobs that StorageForge did not deploy.

An imported job stays what it is: the host's config, cron lines and timers keep running it, and StorageForge never swaps
them for storageforge-job. It gets a row in jobs (plan_id NULL, spec['imported'] true), so state, alerts, the 3-2-1 matrix
and the Files map see it like any other. Such a job cannot report, so its runs are read from what it leaves: a snapshot
newer than the last one seen is a good run, and a rsnapshot log line with an error is a failed one.

Actions are signed scripts, chosen by tool. Forgetting a job only removes the row: nothing on the host changes.
"""
from __future__ import annotations

import json
import re
import shlex
import time
import uuid

from . import deploy, snapfind
from .alerts import get_setting, set_setting
from .db import Conn, loads
from .moves import host_slug
from .remote import is_under
from .scriptkit import HELPERS, PACKAGES, need_line

TOOLS = ('rsnapshot', 'snapper')
HARD_LINKS = {'ext2', 'ext3', 'ext4', 'xfs', 'f2fs', 'jfs', 'reiserfs', 'nilfs2', 'bcachefs', 'btrfs', 'nfs', 'nfs4', 'zfs'}
NO_HARD_LINKS = {'vfat', 'msdos', 'exfat', 'fuse.exfat', 'cifs', 'smb3', 'fuseblk'}
ORPHAN_LEVELS = ('hourly', 'daily', 'weekly', 'monthly', 'alpha', 'beta', 'gamma', 'delta')
SNAPPER_NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,30}')
RUN_NS = uuid.UUID('6d1f0c3a-5a2e-4a39-9a55-0b5f4f6f7c11')    # so a snapshot seen by two scans is one run
READ_ONLY = ('dryrun', 'log', 'snapshots')
VERBS = ('run', 'dryrun', 'pause', 'resume', 'log', 'snapshots')


def is_imported(j: dict) -> bool:
    return bool((j.get('spec') or {}).get('imported'))


def job_key(host: str, tool: str, config: str) -> str:
    return f'x-{"rs" if tool == "rsnapshot" else "sn"}-{uuid.uuid5(RUN_NS, f"{host_slug(host)}|{tool}|{config}").hex[:12]}'


# ── which tool suits which filesystem ───────────────────────────────
def recommend(fstype: str | None) -> dict:
    """What takes snapshots of data on this filesystem: {tool, level, why}. tool None: neither of these."""
    fs = (fstype or '').lower()
    if fs == 'btrfs':
        return {'tool': 'snapper', 'level': 'ok', 'why': 'btrfs snapshots are instant and share space. Use rsnapshot only to keep them on another disk.'}
    if fs == 'zfs':
        return {'tool': None, 'level': 'ok', 'why': 'ZFS has its own snapshots: use a ZFS snapshot storage task, or sanoid.'}
    if fs in NO_HARD_LINKS:
        return {'tool': None, 'level': 'crit', 'why': f'{fs} has no hard links here, so rsnapshot would store a full copy per snapshot, and it has no snapshots of its own. Reformat it, or use a mirror job.'}
    if fs in HARD_LINKS:
        return {'tool': 'rsnapshot', 'level': 'ok', 'why': f'{fs} has no snapshots of its own that snapper can use, and hard links work, so rsnapshot fits.'}
    return {'tool': 'rsnapshot', 'level': 'note', 'why': f'unknown filesystem {fs or "(none reported)"}: rsnapshot works wherever hard links do.'}


def fit(job: dict) -> list[dict]:
    """What is odd about this job on this filesystem. Empty when it suits."""
    tool, fs, out = job['tool'], (job.get('fstype') or '').lower(), []
    if job.get('root_exists') is False:
        out.append({'level': 'warn', 'text': f'{job.get("root")} does not exist now: is the disk or card mounted?'})
    if tool == 'rsnapshot' and fs:
        if fs in NO_HARD_LINKS:
            out.append({'level': 'crit', 'text': f'snapshots are on {fs}, which has no hard links: each one is a full copy.'})
        elif fs == 'btrfs' and job.get('mount') and all(b['src'].startswith('/') and is_under(b['src'], job['mount']) for b in job.get('backups') or [{'src': ''}]):
            out.append({'level': 'note', 'text': 'source and snapshots share one btrfs volume: snapper would be instant and smaller, but rsnapshot is safe to keep.'})
    if tool == 'snapper':
        if fs and fs != 'btrfs':
            out.append({'level': 'note', 'text': f'snapper on {fs} only works on thin LVM volumes. StorageForge can run it but cannot check that.'})
        if job.get('readable') and job.get('timeline') and not job.get('timer_on'):
            out.append({'level': 'warn', 'text': 'TIMELINE_CREATE is on but snapper-timeline.timer is not enabled: no snapshots are being taken.'})
        if job.get('readable') and job.get('cleanup') and not job.get('cleanup_on'):
            out.append({'level': 'warn', 'text': 'cleanup is on but snapper-cleanup.timer is not enabled: old snapshots are not being removed.'})
    if tool == 'rsnapshot' and job.get('readable') and not job.get('schedule'):
        out.append({'level': 'note', 'text': 'no cron line or timer found for it: a wrapper script may run it, or nothing does.'})
    return out


# ── what a host has ─────────────────────────────────────────────────
def _probe_key(host: str) -> str:
    return f'snapjobs.probe.{host_slug(host)}'


def _inventory(conn: Conn, host: str) -> dict:
    return loads(conn.scalar('SELECT inventory_json FROM hosts WHERE lower(hostname) = lower(:h)', {'h': host})) or {}


def merged(scan: list[dict], probe: list[dict]) -> list[dict]:
    """A scan's view, with the last root probe where the scan user could not see the job or its snapshots."""
    out = {(j['tool'], j['config']): j for j in probe}
    for j in scan:
        seen = out.get((j['tool'], j['config']))
        if not seen or (j.get('readable') and j.get('snapshots')):
            out[(j['tool'], j['config'])] = j
    return list(out.values())


def found_on(conn: Conn, host: str, scan: list[dict] | None = None) -> list[dict]:
    scan = (_inventory(conn, host).get('snapjobs') or []) if scan is None else scan
    return merged(scan, get_setting(conn, _probe_key(host)) or [])


def _orphans(conn: Conn, hid: int, host: str, known: list[str]) -> list[dict]:
    """Folders named like rsnapshot's with no config found for them: the job is there, but we can't say what it is yet."""
    where = ' OR '.join(f"d.path LIKE '%/{lv}.0'" for lv in ORPHAN_LEVELS)
    roots: dict[str, set] = {}
    for (path,) in conn.all(f'SELECT d.path FROM directories d JOIN mounts m ON m.mount_id = d.mount_id WHERE m.host_id = :h AND ({where})', {'h': hid}):
        root, _, level = path.rpartition('/')
        if not re.search(r'/[A-Za-z][\w-]*\.\d+(/|$)', root) and not any(is_under(root, k) for k in known):
            roots.setdefault(root or '/', set()).add(level.removesuffix('.0'))
    return [{'tool': 'rsnapshot', 'orphan': True, 'host': host, 'config': None, 'name': root, 'root': root, 'levels': {lv: None for lv in sorted(lvs)},
             'fit': [{'level': 'note', 'text': 'its snapshots are in the index, but no config was found. Look as root, which also reads root\'s crontab and /root.'}]}
            for root, lvs in sorted(roots.items())]


def candidates(conn: Conn) -> list[dict]:
    """Every job found on every host, marked with its job id once imported."""
    from .jobs import overview
    imported = {(r[0].lower(), *json.loads(r[1]).get('find_key', [None, None])): r[2] for r in conn.all(
        'SELECT runner_host, spec_json, job_id FROM jobs WHERE plan_id IS NULL AND removed_at IS NULL')}
    deployed_roots = [j['dst'] for j in overview(conn) if j['method'] == 'rsnapshot' and j['dst']]
    out = []
    for hid, host, inv in conn.all('SELECT host_id, hostname, inventory_json FROM hosts ORDER BY hostname'):
        found = merged((loads(inv) or {}).get('snapjobs') or [], get_setting(conn, _probe_key(host)) or [])
        for j in found:
            jid = imported.get((host.lower(), j['tool'], j['config']))
            out.append({**j, 'host': host, 'snapshots': j['snapshots'][:1], 'count': len(j['snapshots']), 'job': jid, 'fit': fit(j), 'advice': recommend(j.get('fstype'))})
        known = [j['root'] for j in found if j.get('root')] + deployed_roots
        out.extend(_orphans(conn, hid, host, known))
    return out


def probe(db, conn: Conn, host: str, actor: str | None = None) -> list[dict]:
    """Look again as root: a signed, read-only run of the same search. Remembered until the next one."""
    host = deploy.canonical(conn, host)
    res = deploy.run(db, host, snapfind.SNAPFIND + '\n', kind='job-probe', ref=host, mode='report', actor=actor, timeout=120)
    if res['status'] != 'ok':
        raise ValueError(f'could not look on {host}: {res["output"][-300:]}')
    found = snapfind.parse(res['output'])
    set_setting(conn, _probe_key(host), found, actor or 'scan')
    refresh(conn, host, merged(_inventory(conn, host).get('snapjobs') or [], found))
    return found


# ── imported rows ───────────────────────────────────────────────────
def _schedule(found: dict) -> str | None:
    """How often the lowest level runs, as jobs.period() reads it. None: nothing found that says, so it is never late."""
    live = found.get('schedule') or []
    low = found.get('lowest')
    chosen = next((e for e in live if e.get('level') == low and e.get('calendar')), None) or next((e for e in live if e.get('calendar')), None)
    return chosen['calendar'] if chosen else None


_REMOTE_SRC = re.compile(r'(?:[^@\s/:]+@)?(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9.-]*):(?P<path>/\S*)')


def remote_source(src: str) -> tuple[str, str] | None:
    """[user@]host:/path from a backup line, as (host, path). None for a local path, an rsync daemon (host::module,
    rsync://) or anything else that names no folder on a host."""
    m = _REMOTE_SRC.fullmatch(src or '')
    if not m or m['path'].startswith('//'):      # rsync://host/module
        return None
    return m['host'].strip('[]'), m['path'].rstrip('/') or '/'


def remote_sources(backups: list[dict]) -> list[dict]:
    """The backup lines of an rsnapshot config that pull from another host: [{host, path, dst}], host as the config names it."""
    return [{'host': r[0], 'path': r[1], 'dst': b.get('dst')} for b in backups or [] if (r := remote_source(b.get('src') or ''))]


def _alnum(name: str) -> str:
    return re.sub(r'[^a-z0-9]', '', host_slug(name))


def resolve_host(known: list[tuple], name: str) -> str:
    """The scanned host a config's host name means. known: (hostname, ssh_host, ip) rows. By name, address or short name,
    then ignoring dashes and dots (rpi02-docker is rpi02docker) when only one host matches. Otherwise the name as given."""
    n = (name or '').lower()
    for test in (lambda h, s, i: h.lower() == n or (s or '').lower() == n or (i or '') == n,
                 lambda h, s, i: host_slug(h) == host_slug(n)):
        hit = [h for h, s, i in known if test(h, s, i)]
        if hit:
            return hit[0]
    loose = [h for h, _, _ in known if _alnum(h) and _alnum(h) == _alnum(n)]
    return loose[0] if len(loose) == 1 else name


def _spec(found: dict) -> dict:
    local = [b['src'] for b in found.get('backups') or [] if b['src'].startswith('/')]
    is_snapper = found['tool'] == 'snapper'
    return {'imported': True, 'find_key': [found['tool'], found['config']], 'tool': found['tool'], 'config': found['config'], 'root': found.get('root'),
            'src': found.get('root') if is_snapper else (local[0] if local else None),     # a remote line is not a path here: see remote_sources()
            'sources': [found['root']] if is_snapper and found.get('root') else local, 'dst': None if is_snapper else found.get('root'),
            'backups': found.get('backups') or [], 'levels': found.get('levels') or {}, 'lowest': found.get('lowest'), 'schedule': found.get('schedule') or [],
            'fstype': found.get('fstype') or '', 'mount': found.get('mount') or '', 'root_exists': found.get('root_exists'),
            'sync_first': bool(found.get('sync_first')), 'logfile': found.get('logfile'), 'count': len(found.get('snapshots') or []),
            'fit': fit(found), 'keep': ' '.join(f'{k}={v}' for k, v in (found.get('levels') or {}).items())}


def _name(found: dict) -> str:
    if found['tool'] == 'snapper':
        return f'snapper {found["config"]}: {found.get("root") or "?"}'
    sources = [b['src'] for b in found.get('backups') or []]
    what = sources[0] + (f' +{len(sources) - 1}' if len(sources) > 1 else '') if sources else found['config']
    return f'rsnapshot {what} -> {found.get("root") or "?"}'


def _paused(found: dict) -> bool:
    entries = found.get('schedule') or []
    return bool(entries) and not any(e.get('enabled') for e in entries)


def _note_runs(conn: Conn, jid: str, found: dict):
    """What the job left, as runs. Only ever adds: a snapshot rotated away keeps its line in the history."""
    from .jobs import ingest
    low = (found.get('snapshots') or [None])[0]
    now = time.time()
    if low and low['time'] and low['time'] <= now + 600:
        ingest(conn, {'run': str(uuid.uuid5(RUN_NS, f'{jid}|{low["time"]}')), 'job': jid, 'kind': 'run', 'level': low['name'].split('.')[0][:20] if '.' in low['name'] else None,
                      'start': low['time'], 'end': low['time'], 'rc': 0, 'message': f'snapshot {low["name"]} seen'}, 'scan')
    line = found.get('last_line') or ''
    if re.search(r'ERROR|with some errors', line):
        when = _log_time(line) or 0
        if when and when <= now + 600:
            ingest(conn, {'run': str(uuid.uuid5(RUN_NS, f'{jid}|{line}')), 'job': jid, 'kind': 'run', 'start': when, 'end': when, 'rc': 1, 'message': line[:300]}, 'scan')


def _log_time(line: str) -> int | None:
    m = re.match(r'\[(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)', line)
    if m:
        return int(time.mktime(time.strptime(m[1], '%Y-%m-%dT%H:%M:%S')))
    m = re.match(r'\[(\d\d/[A-Za-z]{3}/\d{4}:\d\d:\d\d:\d\d)', line)
    return int(time.mktime(time.strptime(m[1], '%d/%b/%Y:%H:%M:%S'))) if m else None


def import_job(conn: Conn, host: str, tool: str, config: str, actor: str) -> str:
    """Start tracking a job found on a host. Changes nothing there. Returns the job id."""
    if tool not in TOOLS:
        raise ValueError('tool must be rsnapshot or snapper')
    host = deploy.canonical(conn, host)
    found = next((j for j in found_on(conn, host) if j['tool'] == tool and j['config'] == config), None)
    if not found:
        raise LookupError(f'no {tool} job {config} found on {host}: rescan it, or look as root')
    if not found.get('readable', True) or not found.get('root'):
        raise ValueError(f'{config} can\'t be read by the scan account: look on {host} as root first')
    jid = job_key(host, tool, config)
    conn.execute('DELETE FROM jobs WHERE job_id = :j', {'j': jid})      # a job forgotten earlier comes back as new
    conn.execute("""INSERT INTO jobs (job_id, name, method, runner_host, source_host, schedule, spec_json, paused, deployed_at)
                    VALUES (:j, :n, :m, :h, :h, :s, :sp, :p, :t)""",
                 {'j': jid, 'n': _name(found), 'm': tool, 'h': host, 's': _schedule(found), 'sp': json.dumps(_spec(found)), 'p': 1 if _paused(found) else 0, 't': int(time.time())})
    _note_runs(conn, jid, found)
    return jid


def refresh(conn: Conn, host: str, found: list[dict]) -> int:
    """Bring imported jobs up to date with what a scan or probe saw. A job not seen keeps its row, marked missing."""
    by_key = {(j['tool'], j['config']): j for j in found}
    n = 0
    for jid, spec, paused in conn.all('SELECT job_id, spec_json, paused FROM jobs WHERE plan_id IS NULL AND removed_at IS NULL AND lower(runner_host) = lower(:h)', {'h': host}):
        spec = json.loads(spec or '{}')
        j = by_key.get(tuple(spec.get('find_key') or ()))
        if j is None or (not j.get('readable', True) and not j.get('root')):
            if j is None and not spec.get('missing'):
                conn.execute('UPDATE jobs SET spec_json = :s WHERE job_id = :j', {'s': json.dumps({**spec, 'missing': True}), 'j': jid})
            continue
        conn.execute('UPDATE jobs SET name = :n, schedule = :sc, spec_json = :s, paused = :p WHERE job_id = :j',
                     {'n': _name(j), 'sc': _schedule(j), 's': json.dumps(_spec(j)), 'p': 1 if _paused(j) or (paused and j['tool'] == 'snapper' and not j.get('timeline')) else 0, 'j': jid})
        _note_runs(conn, jid, j)
        n += 1
    return n


def after_scan(db, conn: Conn, host: str, scan: list[dict] | None, log=print):
    """After each scan. Snapshot folders are often root's alone, so a job the scan could not see gets a signed look too,
    without which it would look late. Hosts with nothing imported, or no deploy access, are left alone."""
    scan = scan or []
    refresh(conn, host, found_on(conn, host, scan))
    tracked = [json.loads(r[0]).get('find_key') for r in conn.all(
        'SELECT spec_json FROM jobs WHERE plan_id IS NULL AND removed_at IS NULL AND lower(runner_host) = lower(:h)', {'h': host})]
    seen = {(j['tool'], j['config']) for j in scan if j.get('readable') and j.get('snapshots')}
    if any(k and tuple(k) not in seen for k in tracked) and deploy.ready(conn, host):
        try:
            probe(db, conn, host, 'scan')
        except Exception as exc:
            log(f'  imported jobs: {exc}')


def forget(conn: Conn, jid: str):
    from .jobs import get
    j = get(conn, jid)
    if not is_imported(j):
        raise ValueError('only imported jobs can be forgotten: remove a deployed job from its plan')
    conn.execute('UPDATE jobs SET removed_at = :t WHERE job_id = :j', {'t': int(time.time()), 'j': jid})


# ── scripts: every value only ever as one quoted word ───────────────
HEAD = r"""set -uo pipefail
die() { echo "$*" >&2; exit 1; }
conf_ok() { # a config runs cmd_preexec as root: refuse one that anybody but root could have written
  local c=$1; [[ -f $c ]] || die "$c is gone"
  [[ $(stat -c %u -- "$c") == 0 ]] || die "$c is not owned by root: not running it as root"
  (( (8#$(stat -c %a -- "$c")) & 8#022 )) && die "$c can be written by others: not running it as root"
  command -v rsnapshot >/dev/null || die "rsnapshot is not installed here"
}
"""
CRON_FUNCS = r"""swap_line() { # file from to: exact lines only, keeping the file's owner and mode
  local tmp; tmp=$(mktemp) || return 1
  FROM=$2 TO=$3 awk '$0 == ENVIRON["FROM"] { print ENVIRON["TO"]; n = 1; next } { print } END { exit !n }' "$1" >"$tmp" && cat "$tmp" >"$1" && echo "changed a line in $1" || echo "line not found in $1"
  rm -f "$tmp"
}
swap_crontab() { # user from to
  crontab -u "$1" -l | FROM=$2 TO=$3 awk '$0 == ENVIRON["FROM"] { print ENVIRON["TO"]; next } { print }' | crontab -u "$1" - && echo "changed $1's crontab"
}
"""


def _safe_path(p: str | None, what: str = 'path') -> str:
    if not p or not p.startswith('/') or '\n' in p or '/../' in p + '/':
        raise ValueError(f'bad {what} {p!r}')
    return p


def _rs_guard(spec: dict) -> str:
    q = shlex.quote
    conf, root, mount = _safe_path(spec['config'], 'config'), _safe_path(spec['root'], 'snapshot root'), spec.get('mount') or '/'
    guard = f'conf_ok {q(conf)}\n'
    if mount != '/':      # so a card that is not in does not turn into a full copy onto the system disk
        guard += f'mountpoint -q {q(_safe_path(mount))} || die {q(mount + " is not mounted: not running")}\n'
    return guard + f'[[ -d {q(root)} ]] || die {q(root + " does not exist: is its disk mounted?")}\n'


def _sn(spec: dict) -> str:
    if not re.fullmatch(r'[\w.:+@-]+', spec['config'] or ''):
        raise ValueError('bad snapper config name')
    return f'snapper -c {shlex.quote(spec["config"])}'


def _schedule_lines(spec: dict, pause: bool) -> str:
    q, lines = shlex.quote, []
    for e in spec.get('schedule') or []:
        if e['kind'] == 'timer':
            if not re.fullmatch(r'[\w@.:-]+', e['unit']):
                raise ValueError('bad unit name')
            lines.append(f'systemctl {"disable" if pause else "enable"} --now {q(e["unit"] + ".timer")} && echo {q(("paused " if pause else "resumed ") + e["unit"])}')
        elif e['kind'] == 'script':
            lines.append(f'chmod {"a-x" if pause else "u+x,go+rx"} {q(_cron_file(e["file"]))} && echo {q(("paused " if pause else "resumed ") + e["file"])}')
        else:
            plain, stopped = e['line'], snapfind.PAUSED + e['line']
            frm, to = (plain, stopped) if pause else (stopped, plain)
            if e['file'].startswith('crontab:'):
                lines.append(f'swap_crontab {q(e["file"].split(":", 1)[1])} {q(frm)} {q(to)}')
            else:
                lines.append(f'swap_line {q(_cron_file(e["file"]))} {q(frm)} {q(to)}')
    return '\n'.join(lines) + '\n'


def _cron_file(f: str) -> str:
    if not re.match(r'/etc/(crontab$|cron\.(d|hourly|daily|weekly|monthly)/)', f or '') or '/../' in f:
        raise ValueError(f'{f!r} is not a cron file')
    return f


def script(j: dict, verb: str) -> str:
    q, spec, jid = shlex.quote, j['spec'], j['id']
    if verb not in VERBS:
        raise ValueError(f'{verb} is not for imported jobs')
    unit = f'sf-import-{jid}'
    if spec['tool'] == 'rsnapshot':
        conf, low = spec['config'], spec.get('lowest')
        if verb in ('run', 'dryrun') and not low:
            raise ValueError('its config has no retain lines')
        if verb == 'run':
            first = 'rsnapshot -c "$1" sync && ' if spec.get('sync_first') else ''
            inner = first + 'exec rsnapshot -c "$1" "$2"'
            return (HEAD + _rs_guard(spec) + f'systemd-run --no-block --collect --unit="{unit}-$(date +%s)" -p Nice=10 -p IOSchedulingClass=idle '
                    f'sh -c {q(inner)} sh {q(conf)} {q(low)} && echo {q("started rsnapshot " + low)}\n')
        if verb == 'dryrun':
            return HEAD + _rs_guard(spec) + f'rsnapshot -c {q(conf)} configtest\nrsnapshot -c {q(conf)} -t {q(low)}\n'
        if verb == 'log':
            tail = f'[[ -r {q(spec["logfile"])} ]] && tail -n 200 {q(spec["logfile"])}\n' if spec.get('logfile') else 'echo "(its config sets no logfile)"\n'
            return f'journalctl -u {q(unit + "-*")} -n 100 --no-pager -o short-iso 2>&1 || true\n{tail}'
        if verb == 'snapshots':
            root = _safe_path(spec['root'], 'snapshot root')
            return (f'find {q(root)} -mindepth 1 -maxdepth 1 -type d -printf \'%f\\t%T@\\n\' | while IFS=$\'\\t\' read -r n t; do '
                    r'''[[ $n =~ ^[A-Za-z][A-Za-z0-9_-]*\.[0-9]+$ ]] && printf '{"name": "%s", "time": %s}\n' "$n" "${t%.*}"; done; true''' + '\n')
    else:
        sn = _sn(spec)
        if verb == 'run':
            return HEAD + f'{sn} create -c timeline -d {q("StorageForge: Run now")} && echo "snapshot taken"\n'
        if verb == 'dryrun':
            return HEAD + f'{sn} get-config\necho\n{sn} list\n'
        if verb == 'log':
            return 'journalctl -u snapper-timeline.service -u snapper-cleanup.service -n 200 --no-pager -o short-iso 2>&1 || true\n'
        if verb == 'snapshots':
            root = _safe_path(spec['root'], 'subvolume')
            return (f'find {q(root.rstrip("/") + "/.snapshots")} -mindepth 1 -maxdepth 1 -type d -printf \'%f\\t%T@\\n\' | while IFS=$\'\\t\' read -r n t; do '
                    r'''[[ $n =~ ^[0-9]+$ ]] && printf '{"name": "%s", "time": %s}\n' "$n" "${t%.*}"; done; true''' + '\n')
        extra = 'systemctl enable --now snapper-timeline.timer snapper-cleanup.timer\n' if verb == 'resume' else ''
        return HEAD + f'{sn} set-config TIMELINE_CREATE={"no" if verb == "pause" else "yes"} && echo {q(("paused" if verb == "pause" else "resumed") + " timeline snapshots of " + spec["config"])}\n{extra}'
    if not spec.get('schedule'):      # pause or resume, rsnapshot
        raise ValueError('no cron line or timer was found for this job, so there is nothing to pause')
    return HEAD + CRON_FUNCS + _schedule_lines(spec, verb == 'pause')


def action(db, conn: Conn, j: dict, verb: str, actor: str) -> dict:
    res = deploy.run(db, j['runner'], script(j, verb), kind='job-action', ref=f'{j["id"]}:{verb}', mode='apply', actor=actor, timeout=600)
    if verb in ('pause', 'resume') and res['status'] == 'ok':
        conn.execute('UPDATE jobs SET paused = :p WHERE job_id = :j', {'p': 1 if verb == 'pause' else 0, 'j': j['id']})
    if verb == 'snapshots' and res['status'] == 'ok':
        snaps = sorted((json.loads(l) for l in res['output'].splitlines() if l.startswith('{')), key=lambda s: -s['time'])
        res['snapshots'] = snaps
        _note_runs(conn, j['id'], {'snapshots': snaps})
    return res


def _snapshot_dir(spec: dict, snapshot: str, rel: str) -> str:
    good = re.fullmatch(r'\d+', snapshot or '') if spec['tool'] == 'snapper' else re.fullmatch(r'[A-Za-z][\w-]*\.\d+', snapshot or '')
    if not good:
        raise ValueError('bad snapshot name')
    if '..' in (rel or '').split('/') or (rel or '').startswith('/') or '\n' in (rel or ''):
        raise ValueError('bad path')
    root = _safe_path(spec['root'], 'snapshot root').rstrip('/')
    return f'{root}/.snapshots/{snapshot}/snapshot' if spec['tool'] == 'snapper' else f'{root}/{snapshot}'


# a link inside a snapshot must not lead root out of it
_INSIDE = r"""b=$(readlink -f -- "$BASE") || die "no such snapshot"
t=$(readlink -m -- "$BASE/$REL")
[[ $t == "$b" || $t == "$b"/* ]] || die "that path leads out of the snapshot"
[[ -e $t ]] || die "no such path in this snapshot"
"""


def browse(db, conn: Conn, j: dict, snapshot: str, rel: str, actor: str) -> dict:
    q = shlex.quote
    base = _snapshot_dir(j['spec'], snapshot, rel)
    res = deploy.run(db, j['runner'], HEAD + f'BASE={q(base)} REL={q(rel or "")}\n' + _INSIDE +
                     r"""find "$t" -mindepth 1 -maxdepth 1 \( -type d -o -type f -o -type l \) -printf '%y\t%s\t%T@\t%f\n' | sort -t$'\t' -k4 | head -n 3000""" + '\n',
                     kind='job-action', ref=f'{j["id"]}:ls', mode='apply', actor=actor, timeout=120)
    entries = []
    for line in res['output'].splitlines():
        parts = line.split('\t')
        if len(parts) == 4 and parts[0] in ('d', 'f', 'l'):
            entries.append({'type': parts[0], 'size': int(parts[1] or 0), 'mtime': int(float(parts[2] or 0)), 'name': parts[3]})
    return {'job': j['id'], 'snapshot': snapshot, 'path': rel, 'entries': entries, 'error': None if res['status'] == 'ok' else res['output'][-500:]}


def original_of(spec: dict, rel: str) -> str:
    """Where a path inside a snapshot came from."""
    rel = (rel or '').strip('/')
    if not rel:
        raise ValueError('pick a file or folder to restore')
    if spec['tool'] == 'snapper':
        return f'{spec["root"].rstrip("/")}/{rel}'
    for b in spec.get('backups') or []:
        dst = b['dst'].strip('/')
        if rel == dst or rel.startswith(dst + '/'):
            if not b['src'].startswith('/'):
                raise ValueError(f'{b["src"]} is on another host: restore it there from {b["dst"]} by hand')
            return b['src'].rstrip('/') + rel[len(dst):]
    raise ValueError('that path is not inside any backup line of this job: open one of its folders')


def restore_target(j: dict, snapshot: str, rel: str) -> tuple[str, str]:
    _snapshot_dir(j['spec'], snapshot, rel)
    original = _safe_path(original_of(j['spec'], rel))
    return f'{original}.restored-{time.strftime("%Y%m%d-%H%M%S")}', original.rsplit('/', 1)[0] or '/'


def restore(db, j: dict, snapshot: str, rel: str, target: str, actor: str, gid: str | None = None) -> dict:
    q = shlex.quote
    base = _snapshot_dir(j['spec'], snapshot, rel)
    script_ = (HEAD + f'BASE={q(base)} REL={q(rel)} TARGET={q(_safe_path(target))}\n' + _INSIDE +
               '[[ -e $TARGET ]] && die "$TARGET already exists"\nmkdir -p -- "$(dirname -- "$TARGET")"\n'
               'cp -a --reflink=auto -- "$t" "$TARGET" && echo "restored to $TARGET"\n')
    res = deploy.run(db, j['runner'], script_, kind='restore', ref=j['id'], mode='apply', actor=actor, group_id=gid, timeout=6 * 3600)
    return {**res, 'target': target}


def retention(db, conn: Conn, jid: str, keep: dict, actor: str) -> dict:
    """Change how many snapshots each existing level keeps. On the next cleanup or rotation, the host deletes any beyond that."""
    from .jobs import get
    j = get(conn, jid)
    if not is_imported(j):
        raise ValueError('a deployed job\'s retention is set in its plan')
    spec, q = j['spec'], shlex.quote
    if not keep or not isinstance(keep, dict):
        raise ValueError('say how many to keep for which level')
    for level, n in keep.items():
        if level not in spec['levels']:
            raise ValueError(f'this job has no level {level}: only the counts of existing levels can change')
        if not isinstance(n, int) or isinstance(n, bool) or not 0 <= n <= 9999 or (spec['tool'] == 'rsnapshot' and n < 1):
            raise ValueError(f'bad count for {level}')
    if spec['tool'] == 'snapper':
        names = ' '.join(q(f'{"NUMBER_LIMIT" if lv == "number" else "TIMELINE_LIMIT_" + lv.upper()}={n}') for lv, n in keep.items())
        body = HEAD + f'{_sn(spec)} set-config {names} && echo "retention set"\n'
    else:
        conf = q(_safe_path(spec['config'], 'config'))
        body = HEAD + f'conf_ok {conf}\ncp -p -- {conf} {conf}.sf-bak\ntmp=$(mktemp)\n'
        for lv, n in keep.items():
            body += (f'''LEVEL={q(lv)} KEEP={q(str(n))} awk -F'\\t' -v OFS='\\t' '($1 == "retain" || $1 == "interval") && $2 == ENVIRON["LEVEL"] {{ $3 = ENVIRON["KEEP"] }} {{ print }}' {conf} >"$tmp" && cat "$tmp" >{conf}\n''')
        body += (f'rm -f "$tmp"\nif ! rsnapshot -c {conf} configtest; then cat {conf}.sf-bak >{conf}; die "rsnapshot refused it: the config is back as it was"; fi\n'
                 f'echo "retention set (the old config is {spec["config"]}.sf-bak)"\n')
    res = deploy.run(db, j['runner'], body, kind='job-action', ref=f'{jid}:retention', mode='apply', actor=actor, timeout=120)
    if res['status'] == 'ok':
        spec['levels'].update(keep)
        spec['keep'] = ' '.join(f'{k}={v}' for k, v in spec['levels'].items())
        conn.execute('UPDATE jobs SET spec_json = :s WHERE job_id = :j', {'s': json.dumps(spec), 'j': jid})
    return res


# ── starting something new ──────────────────────────────────────────
def advice_for(conn: Conn, host: str, path: str) -> dict:
    """Which tool for this folder, from the host's last scan."""
    from .moves import find_host, hosts, mount_of
    h = find_host(hosts(conn), host)
    if not h:
        raise LookupError(f'{host} has not been scanned')
    m = mount_of(h, _safe_path(path)) or {}
    return {'host': h['name'], 'path': path, 'fstype': m.get('fstype'), 'mount': m.get('target'), **recommend(m.get('fstype'))}


def create_snapper(db, conn: Conn, host: str, path: str, name: str, actor: str) -> dict:
    """snapper create-config on a btrfs subvolume, then import it. The host checks the filesystem again before it starts."""
    q = shlex.quote
    if not SNAPPER_NAME.fullmatch(name or ''):
        raise ValueError('a snapper config name is lower-case letters, digits, - and _')
    a = advice_for(conn, host, path)
    if a['fstype'] != 'btrfs':
        raise ValueError(f'{path} is on {a["fstype"] or "an unknown filesystem"}: {a["why"]}')
    p, n = q(_safe_path(path)), q(name)
    body = (HELPERS + PACKAGES + 'APPLY=1\n' + need_line('snapper') + 'set -uo pipefail\ndie() { echo "$*" >&2; exit 1; }\n'
            'command -v snapper >/dev/null || die "snapper could not be installed"\n'
            f'[[ $(findmnt -n -o FSTYPE --target {p}) == btrfs ]] || die {q(path + " is not on btrfs")}\n'
            f'[[ ! -e /etc/snapper/configs/{name} ]] || die {q("there is already a snapper config " + name)}\n'
            f'snapper -c {n} create-config {p} || die "snapper refused: the path must be a btrfs subvolume"\n'
            'systemctl enable --now snapper-timeline.timer snapper-cleanup.timer || echo "could not enable the snapper timers"\n'
            f'echo {q("created snapper config " + name)}\n')
    res = deploy.run(db, a['host'], body, kind='job-action', ref=f'snapper:{name}', mode='apply', actor=actor, timeout=600)
    if res['status'] != 'ok':
        return res
    probe(db, conn, a['host'], actor)
    return {**res, 'job': import_job(conn, a['host'], 'snapper', name, actor)}
