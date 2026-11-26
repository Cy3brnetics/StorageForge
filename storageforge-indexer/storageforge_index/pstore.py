"""pstore: the last words of a kernel that crashed, read by the scan after the host is back (roadmap section 3, phase 5).

When a kernel panics or oopses, it writes the end of its log into persistent storage that survives a reboot: EFI variables, a
reserved piece of RAM (ramoops), or the firmware's ERST. After the reboot they show as files under /sys/fs/pstore, and systemd-pstore
(systemd 243 and newer) moves them into /var/lib/systemd/pstore at boot. The scan lists both with the scan user's own find (which
the access script gives CAP_DAC_READ_SEARCH, so it can list what root can), and reads the newest records where the scan user may:
the files are root's, so a scan user that is not root lists them and says so, and one that is root reads them.

What is read is stored as the host's lines with via 'pstore', at the time the record was written, the last LINES_PER_FILE lines of
each file. They are history, so they raise no log rule; a crash record written in the last ALERT_DAYS is one warning per host in the
notification center (log-pstore), with the record's last line when it could be read, whether or not it could. A record is the
host's kernel's word written before the crash, and root on the host can write or delete one: it says why a host died when nothing
else does, and proves nothing.
"""
from __future__ import annotations

import hashlib
import re
import time

from . import hostlogs
from .db import Conn
from .remote import READONLY_DIR

FILES, FILE_BYTES, LINES_PER_FILE = 6, 32768, 300
ALERT_DAYS = 3
ROOTS = '/sys/fs/pstore /var/lib/systemd/pstore'

SCRIPT = r"""PATH="$PATH:/usr/sbin:/sbin"
F=__DIR__/find; [ -x "$F" ] || F=find
echo "@@who $(id -u)"
echo '@@records'
"$F" __ROOTS__ -maxdepth 2 -type f -printf '%T@ %s %p\n' 2>/dev/null | sort -rn | head -n 40
"$F" __ROOTS__ -maxdepth 2 -type f -name 'dmesg*' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -n __FILES__ | while read -r at path; do
  if [ -r "$path" ]; then echo "@@file ${at%%.*} $path"; head -c __BYTES__ "$path" 2>/dev/null | tr -d '\000' | sed 's/^/|/'; echo; else echo "@@denied ${at%%.*} $path"; fi
done
echo '@@end'
""".replace('__DIR__', READONLY_DIR).replace('__ROOTS__', ROOTS).replace('__FILES__', str(FILES)).replace('__BYTES__', str(FILE_BYTES))

_PATH = re.compile(r'/(sys/fs/pstore|var/lib/systemd/pstore)/[A-Za-z0-9_.:/-]{1,200}')
_KMSG = re.compile(r'<(\d{1,3})>(?:\[\s*\d+\.\d+\]\s?)?(.*)')
_STAMP = re.compile(r'\[\s*\d+\.\d+\]\s?(.*)')


def parse(output: str, now: float | None = None) -> dict:
    """{'root': bool, 'records': [{at, size, path}], 'files': [{at, path, lines}], 'denied': [{at, path}], 'finished': bool}. A host may send
    anything: what cannot be read is skipped."""
    now = time.time() if now is None else now
    out = {'root': False, 'records': [], 'files': [], 'denied': [], 'finished': False}
    section, current = None, None
    for raw in str(output or '').splitlines():
        if raw.startswith('@@who '):
            out['root'] = raw[6:].strip() == '0'
        elif raw == '@@records':
            section, current = 'records', None
        elif raw == '@@end':
            out['finished'], section, current = True, None, None
        elif raw.startswith('@@file ') or raw.startswith('@@denied '):
            parts = raw.split(' ', 2)
            if len(parts) == 3 and parts[1].isdigit() and _PATH.fullmatch(parts[2]) and '/..' not in parts[2]:
                at = min(int(parts[1]), int(now))
                if parts[0] == '@@file':
                    current = {'at': at, 'path': parts[2], 'lines': []}
                    out['files'].append(current)
                else:
                    out['denied'].append({'at': at, 'path': parts[2]})
                    current = None
            section = 'file' if parts[0] == '@@file' else None
        elif section == 'records':
            bits = raw.split(' ', 2)
            if len(bits) == 3 and _PATH.fullmatch(bits[2]) and '/..' not in bits[2]:
                try:
                    out['records'].append({'at': min(int(float(bits[0])), int(now)), 'size': int(bits[1]), 'path': bits[2]})
                except ValueError:
                    continue
        elif section == 'file' and current is not None and raw.startswith('|'):
            current['lines'].append(raw[1:])
    for f in out['files']:
        f['lines'] = [x for x in f['lines'] if x.strip()][-LINES_PER_FILE:]
    return out


def lines_of(host: str, f: dict) -> list[dict]:
    """A record's lines as hostlogs lines. A line keeps its level when the kernel wrote one (<3>...), and the record's order by a
    microsecond each, so the newest line of a record is its last."""
    out = []
    base = int(f['at'] * 1e6) - len(f['lines'])
    for i, raw in enumerate(f['lines']):
        m = _KMSG.match(raw)
        priority, text = (int(m[1]) & 7, m[2]) if m else (6, (_STAMP.match(raw) or [None, raw])[1])
        message = hostlogs.kernel_message(text)
        if not message:
            continue
        key = hashlib.sha256(f'pstore|{f["path"]}|{f["at"]}|{i}|{message}'.encode('utf-8', 'replace')).hexdigest()[:32]
        out.append(hostlogs.kernel_line(key, base + i, priority, message))
    return out


def store(conn: Conn, host: str, got: dict, now: float | None = None) -> dict:
    """Keeps what one scan read from pstore. Returns {'records', 'read', 'new', 'note'}."""
    now = time.time() if now is None else now
    dmesg = [r for r in got['records'] if r['path'].rsplit('/', 1)[-1].startswith('dmesg')]
    newest = max((r['at'] for r in dmesg), default=None)
    lines = [x for f in got['files'] for x in lines_of(host, f)]
    note = ''
    if got['denied'] and not got['files']:
        note = (f'{len(dmesg)} crash record(s) are in pstore and the scan user cannot read them: they are root\'s. '
                'Read them as root on the host (/var/lib/systemd/pstore or /sys/fs/pstore), or scan as root to have them here.')
    elif not got['finished']:
        note = 'the scan stopped before it had read pstore to the end'
    new = hostlogs.store(conn, host, {'state': 'ok', 'lines': lines, 'cut': False}, now, via='pstore') if lines else 0
    with conn.tx():
        hostlogs.ensure_side_status(conn, host, now)
        conn.execute("""UPDATE host_log_status SET pstore_at = :a, pstore_records = :n, pstore_read = :r, pstore_note = :o, pstore_checked_at = :t WHERE host = :h""",
                     {'a': newest, 'n': len(dmesg), 'r': 1 if got['files'] else 0, 'o': note[:500], 't': int(now), 'h': host})
    return {'records': len(dmesg), 'read': bool(got['files']), 'new': new, 'note': note}


def collect(conn: Conn, t, host: str, log=lambda _: None) -> dict | None:
    """One scan's look at pstore. A failure is said and costs the scan nothing."""
    if not hostlogs.enabled():
        return None
    now = time.time()
    try:
        got = parse(t.run(SCRIPT, timeout=60), now)
    except Exception as exc:
        log(f'  pstore: {exc}')
        return None
    done = store(conn, host, got, now)
    if done['records']:
        log(f'  pstore: {done["records"]} crash record(s)' + (f', {done["new"]} new line(s) read' if done['read'] else f': {done["note"]}'))
    return done


def problems(conn: Conn, now: float | None = None) -> dict:
    """{key: (kind, ref, title, message, level)}: one warning per host with a crash record written in the last ALERT_DAYS."""
    now = time.time() if now is None else now
    out = {}
    for host, at, n, read, note in conn.all('SELECT host, pstore_at, pstore_records, pstore_read, pstore_note FROM host_log_status WHERE pstore_records > 0 AND pstore_at >= :t',
                                            {'t': int(now - ALERT_DAYS * 86400)}):
        last = None
        if read:
            # the newest record's most urgent line, the first of them: what the kernel said when it gave up, before what followed
            last = conn.scalar("""SELECT message FROM host_log_lines WHERE host = :h AND via = 'pstore' AND at_us >= :lo ORDER BY priority, at_us, line_id LIMIT 1""",
                               {'h': host, 'lo': int(at * 1e6) - LINES_PER_FILE - 1})
        when = time.strftime('%Y-%m-%d %H:%M', time.localtime(at))
        what = f'The worst line it holds: {last}' if last else (note or 'it could not be read')
        out[f'log-pstore:{host}'] = ('log-pstore', host, f'The kernel on {host} crashed and left a record',
                                     f'{n} crash record(s) in pstore, the newest written {when}, found after the host came back. {what}', 'warn')
    return out
