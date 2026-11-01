"""Finding rsnapshot and snapper jobs that StorageForge did not deploy. SNAPFIND runs in every scan as the scan user, and
as root through deploy access when a scan could not read enough. It only reads. parse() turns its lines into one dict
per job, for snapjobs.py to offer for import. Nothing here touches the database, so remote.py can use it.
"""
from __future__ import annotations

import re

# POSIX sh, no exit (it runs inside the inventory script). Every value goes through printf %s after a tag, so a line of
# a config can't pass for one of ours. The capability find, where set up, reads snapshot folders a plain user can't.
SNAPFIND = r"""(
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
F=find; [ -x /usr/local/lib/storageforge/find ] && F=/usr/local/lib/storageforge/find
T=; command -v timeout >/dev/null 2>&1 && T='timeout 15'
CRON='/etc/crontab /etc/cron.d/*'
CRONDIRS='/etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*'
UNITS='/etc/systemd/system/*.service /usr/lib/systemd/system/rsnapshot*.service /lib/systemd/system/rsnapshot*.service'
tag() { t=$1; shift; while IFS= read -r l; do printf '%s' "$t"; for a in "$@"; do printf '\t%s' "$a"; done; printf '\t%s\n' "$l"; done; }
where() { d=$1; while [ ! -e "$d" ] && [ "$d" != / ]; do d=$(dirname "$d"); done
  printf '%s\t%s\t%s' "$(findmnt -n -o FSTYPE --target "$d" 2>/dev/null | head -n 1)" "$(findmnt -n -o TARGET --target "$d" 2>/dev/null | head -n 1)" "$([ -e "$1" ] && echo 1 || echo 0)"; }
for f in $CRON $CRONDIRS; do [ -r "$f" ] || continue; x=0; [ -x "$f" ] && x=1; grep -s rsnapshot "$f" | tag C "$f" "$x"; done
crontab -l 2>/dev/null | grep rsnapshot | tag C "crontab:$(id -un)" 1
for f in $UNITS; do [ -r "$f" ] || continue
  e=$(sed -n 's/^ExecStart=//p' "$f" | grep rsnapshot | head -n 1); [ -n "$e" ] || continue
  u=$(basename "$f" .service); cal=
  for t in "/etc/systemd/system/$u.timer" "/usr/lib/systemd/system/$u.timer" "/lib/systemd/system/$u.timer"; do [ -r "$t" ] && { cal=$(sed -n 's/^OnCalendar=//p' "$t" | head -n 1); break; }; done
  printf 'U\t%s\t%s\t%s\t%s\n' "$u" "$(systemctl is-enabled "$u.timer" 2>/dev/null)" "$cal" "$e"
done
{ ls -d /etc/rsnapshot*.conf /etc/rsnapshot.d/*.conf /etc/rsnapshot/*.conf /usr/local/etc/rsnapshot*.conf 2>/dev/null
  $T grep -rlsE '^snapshot_root[[:space:]]' /etc /usr/local/etc /root /home/*/.config/rsnapshot 2>/dev/null
  { for f in $CRON $CRONDIRS $UNITS; do grep -sh rsnapshot "$f"; done; crontab -l 2>/dev/null | grep rsnapshot; } \
    | grep -oE -- '-c[[:space:]]+/[^[:space:];"'"'"']+' | sed -E 's/^-c[[:space:]]+//'
} | grep -vE '^/etc/storageforge/|\.(default|pacnew|pacsave|dpkg-[a-z]+|rpmnew|rpmsave|bak|orig|sf-bak)$|~$' | sort -u | while IFS= read -r c; do
  [ -f "$c" ] || continue
  [ -r "$c" ] || { printf 'N\t%s\n' "$c"; continue; }
  grep -E '^(snapshot_root|retain|interval|backup|logfile|no_create_root|sync_first)[[:space:]]' "$c" | tag R "$c"
  r=$(sed -n -E 's/^snapshot_root[[:space:]]+//p' "$c" | head -n 1); [ -n "$r" ] || continue
  printf 'M\t%s\t%s\n' "$c" "$(where "$r")"
  $F "$r" -mindepth 1 -maxdepth 1 -type d -printf '%f\t%T@\n' 2>/dev/null | tag S "$c"
  lg=$(sed -n -E 's/^logfile[[:space:]]+//p' "$c" | head -n 1)
  [ -n "$lg" ] && [ -r "$lg" ] && tail -n 200 "$lg" | grep -E 'ERROR|completed' | tail -n 1 | tag L "$c"
done
for f in /etc/snapper/configs/*; do [ -e "$f" ] || continue; n=$(basename "$f")
  [ -r "$f" ] || { printf 'O\t%s\n' "$n"; continue; }
  grep -E '^(SUBVOLUME|FSTYPE|TIMELINE_CREATE|TIMELINE_CLEANUP|NUMBER_CLEANUP|NUMBER_LIMIT|TIMELINE_LIMIT_[A-Z]+)=' "$f" | tag P "$n"
  s=$(sed -n 's/^SUBVOLUME="\(.*\)"$/\1/p' "$f"); [ -n "$s" ] || continue
  printf 'W\t%s\t%s\n' "$n" "$(where "$s")"
  $F "${s%/}/.snapshots" -mindepth 1 -maxdepth 1 -type d -printf '%f\t%T@\n' 2>/dev/null | tag Q "$n"
done
for u in snapper-timeline.timer snapper-cleanup.timer; do printf 'G\t%s\t%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null)"; done
) 2>/dev/null"""

PAUSED = '#sf-paused '      # how pausing marks a cron line, so resuming finds exactly the lines it stopped
DEFAULT_CONF = '/etc/rsnapshot.conf'
SNAPPER_LEVELS = ('HOURLY', 'DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY')
_RUN = re.compile(r'rsnapshot(?:\s+-[A-Za-z]+)*(?:\s+-c\s+(?P<conf>[^\s;"\']+))?(?:\s+-[A-Za-z]+)*\s+(?P<level>[A-Za-z][\w-]*)')
_SNAP = re.compile(r'[A-Za-z][\w-]*\.\d+')
_NOT_LEVELS = {'configtest', 'sync', 'du', 'diff', 'help', 'version', 'version-only', 'restore', 'upgrade-config-file', 'get-latest-snapshot'}


def cron_calendar(when: list[str]) -> str | None:
    """A cron time as something jobs.period() reads: only ever used to judge whether a job is late."""
    if len(when) != 5:
        return None
    minute, hour, dom, _, dow = when
    if dow != '*':
        return 'weekly'
    if dom != '*':
        return 'monthly'
    if hour == '*':
        return 'hourly'
    return f'*-*-* {hour.replace("*/", "0/")}:{minute if minute.isdigit() else "00"}:00'


def _cron_entry(file: str, executable: str, line: str) -> dict | None:
    """One line of cron that runs rsnapshot, or None for a comment or a line that only mentions it."""
    paused = line.startswith(PAUSED)
    text = line[len(PAUSED):] if paused else line
    if text.lstrip().startswith('#'):
        return None
    m = _RUN.search(text)
    if not m or m['level'] in _NOT_LEVELS:
        return None
    entry = {'kind': 'cron', 'file': file, 'line': text, 'level': m['level'], 'conf': m['conf'] or DEFAULT_CONF, 'enabled': not paused}
    period = re.fullmatch(r'/etc/cron\.(hourly|daily|weekly|monthly)/.*', file)
    if period:      # a script run-parts starts: there is no time in it, and it is stopped by taking away its x bit
        entry.update(kind='script', enabled=executable == '1', calendar=period[1])
        return entry
    words = text.split()
    nickname = {'@hourly': 'hourly', '@daily': 'daily', '@midnight': 'daily', '@weekly': 'weekly', '@monthly': 'monthly'}.get(words[0] if words else '')
    entry['calendar'] = nickname or cron_calendar(words[:5])
    return entry


def _number(v: str) -> int | None:
    return int(v) if v.isdigit() else None


def parse(text: str) -> list[dict]:
    """SNAPFIND's lines as jobs: {tool, name, config, root, fstype, mount, levels: {level: keep}, backups, schedule,
    snapshots: [{name, time}], newest, readable, ...}. Jobs StorageForge's own scripts installed (sf-* units) are left out."""
    rs, sn, cron, units, global_timers = {}, {}, [], [], {}

    def r(conf):
        return rs.setdefault(conf, {'tool': 'rsnapshot', 'name': conf, 'config': conf, 'root': None, 'levels': {}, 'backups': [], 'schedule': [],
                                    'snapshots': [], 'readable': True, 'fstype': '', 'mount': '', 'root_exists': None, 'last_line': ''})

    def s(name):
        return sn.setdefault(name, {'tool': 'snapper', 'name': name, 'config': name, 'root': None, 'levels': {}, 'backups': [], 'schedule': [],
                                    'snapshots': [], 'readable': True, 'fstype': '', 'mount': '', 'root_exists': None, 'settings': {}})
    for line in (text or '').splitlines():
        f = line.split('\t')
        tag = f[0]
        if tag == 'C' and len(f) >= 4:
            if e := _cron_entry(f[1], f[2], '\t'.join(f[3:])):
                cron.append(e)
        elif tag == 'U' and len(f) >= 5:
            m = _RUN.search(f[4])
            if m and m['level'] not in _NOT_LEVELS:
                units.append({'kind': 'timer', 'unit': f[1], 'enabled': f[2] == 'enabled', 'calendar': f[3] or None, 'level': m['level'], 'conf': m['conf'] or DEFAULT_CONF})
        elif tag == 'N' and len(f) == 2:
            r(f[1])['readable'] = False
        elif tag == 'R' and len(f) >= 3:
            j, fields = r(f[1]), [w for w in f[2:] if w]
            fields = fields if len(fields) > 1 else (fields[0].split() if fields else [''])    # rsnapshot wants tabs, but say what it says
            key, words = fields[0], fields[1:]
            if key == 'snapshot_root' and words:
                j['root'] = words[0].rstrip('/') or '/'
            elif key in ('retain', 'interval') and len(words) >= 2 and words[1].isdigit():
                j['levels'][words[0]] = int(words[1])
            elif key == 'backup' and len(words) >= 2:
                j['backups'].append({'src': words[0], 'dst': words[1]})
            elif key == 'logfile' and words:
                j['logfile'] = words[0]
            elif key == 'no_create_root':
                j['no_create_root'] = words[:1] == ['1']
            elif key == 'sync_first':
                j['sync_first'] = words[:1] == ['1']
        elif tag == 'M' and len(f) == 5:
            r(f[1]).update(fstype=f[2], mount=f[3], root_exists=f[4] == '1')
        elif tag == 'S' and len(f) == 4 and (_SNAP.fullmatch(f[2]) or f[2] == '.sync'):
            r(f[1])['snapshots'].append({'name': f[2], 'time': int(float(f[3] or 0))})
        elif tag == 'L' and len(f) >= 3:
            r(f[1])['last_line'] = '\t'.join(f[2:])
        elif tag == 'O' and len(f) == 2:
            s(f[1])['readable'] = False
        elif tag == 'P' and len(f) == 3 and '=' in f[2]:
            k, _, v = f[2].partition('=')
            s(f[1])['settings'][k] = v.strip().strip('"')
        elif tag == 'W' and len(f) == 5:
            s(f[1]).update(fstype=f[2], mount=f[3], root_exists=f[4] == '1')
        elif tag == 'Q' and len(f) == 4 and f[2].isdigit():
            s(f[1])['snapshots'].append({'name': f[2], 'time': int(float(f[3] or 0))})
        elif tag == 'G' and len(f) == 3:
            global_timers[f[1]] = f[2]
    return _finish_rsnapshot(rs, cron + units) + _finish_snapper(sn, global_timers)


def _finish_rsnapshot(rs: dict, runs: list[dict]) -> list[dict]:
    out = []
    for e in runs:
        if e['conf'] not in rs:
            rs[e['conf']] = {'tool': 'rsnapshot', 'name': e['conf'], 'config': e['conf'], 'root': None, 'levels': {}, 'backups': [], 'schedule': [],
                             'snapshots': [], 'readable': False, 'fstype': '', 'mount': '', 'root_exists': None, 'last_line': ''}
        rs[e['conf']]['schedule'].append({k: v for k, v in e.items() if k != 'conf'})
    for j in rs.values():
        if any(e.get('unit', '').startswith('sf-') for e in j['schedule']):
            continue    # a move script's --install put this here: it is already StorageForge's
        if j['readable'] and not j['root']:
            continue    # a stock config with everything commented out
        j['snapshots'].sort(key=lambda x: -x['time'])
        j['newest'] = j['snapshots'][0]['time'] if j['snapshots'] else None
        j['lowest'] = next(iter(j['levels']), None)
        out.append(j)
    return out


def _finish_snapper(sn: dict, timers: dict) -> list[dict]:
    for j in sn.values():
        st = j.pop('settings')
        j['root'] = st.get('SUBVOLUME') or None
        j['fstype'] = j['fstype'] or st.get('FSTYPE', '')
        for lv in SNAPPER_LEVELS:
            if (n := _number(st.get(f'TIMELINE_LIMIT_{lv}', ''))) is not None:
                j['levels'][lv.lower()] = n
        if (n := _number(st.get('NUMBER_LIMIT', ''))) is not None:
            j['levels']['number'] = n
        j['timeline'] = st.get('TIMELINE_CREATE') == 'yes'
        j['cleanup'] = st.get('TIMELINE_CLEANUP') == 'yes' or st.get('NUMBER_CLEANUP') == 'yes'
        j['timer_on'] = timers.get('snapper-timeline.timer') == 'enabled'
        j['cleanup_on'] = timers.get('snapper-cleanup.timer') == 'enabled'
        if j['timeline'] and j['timer_on']:
            j['schedule'].append({'kind': 'timer', 'unit': 'snapper-timeline.timer', 'enabled': True, 'calendar': 'hourly', 'level': 'timeline'})
        j['snapshots'].sort(key=lambda x: -x['time'])
        j['newest'] = j['snapshots'][0]['time'] if j['snapshots'] else None
        j['lowest'] = 'timeline'
    return list(sn.values())
