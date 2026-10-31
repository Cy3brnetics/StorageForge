"""Disk health and snapshots. SMART and btrfs stats need root, so the scan account gets no new rights: access setup installs
a small root-owned collector that runs hourly and writes one report; scans only read that report (remote.py @@health). A
host without it simply shows no health data. ZFS snapshots need no root, so the scan lists those itself (@@snapshots).
"""
from __future__ import annotations

import datetime as dt
import json
import re
import time

COLLECTOR = r"""#!/bin/sh
# StorageForge disk health, written by access setup. Reads only. Writes one report that the scan user can read.
PATH=$PATH:/usr/sbin:/sbin
out=/var/lib/storageforge/health
mkdir -p "$out"
tmp=$(mktemp "$out/.report.XXXXXX") || exit 1
{
  echo "## at"; date +%s
  if command -v smartctl >/dev/null 2>&1 && command -v lsblk >/dev/null 2>&1; then
    lsblk -dn -o NAME,TYPE | while read -r d t; do
      [ "$t" = disk ] || continue
      echo "## smart $d"; smartctl -j -a "/dev/$d" 2>/dev/null | tr -d '\n'; echo
    done
  fi
  if command -v btrfs >/dev/null 2>&1 && command -v findmnt >/dev/null 2>&1; then
    findmnt -rn -t btrfs -o SOURCE,TARGET | sed 's/\[[^]]*\]//' | sort -u -k1,1 | while read -r _ m; do
      echo "## stats $m"; btrfs device stats -c "$m" 2>/dev/null
      echo "## scrub $m"; btrfs scrub status "$m" 2>/dev/null
      echo "## snaps $m"; btrfs subvolume list -r -s "$m" 2>/dev/null | wc -l
    done
  fi
} >"$tmp"
chgrp @GROUP@ "$tmp" 2>/dev/null; chmod 0640 "$tmp"
mv "$tmp" "$out/report"
"""

# Appended to the access setup. Failing here must not undo working scan access, so it stops only itself.
INSTALL = r"""
( set +e
  mkdir -p /var/lib/storageforge/health; chgrp "$G" /var/lib/storageforge/health; chmod 0750 /var/lib/storageforge/health
  cat >"$D/health" <<'SF_HEALTH'
@COLLECTOR@SF_HEALTH
  chown root:root "$D/health"; chmod 0755 "$D/health"
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    printf '[Unit]\nDescription=StorageForge disk health\n[Service]\nType=oneshot\nExecStart=%s/health\n' "$D" >/etc/systemd/system/sf-health.service
    printf '[Unit]\nDescription=StorageForge disk health\n[Timer]\nOnCalendar=hourly\nPersistent=true\n[Install]\nWantedBy=timers.target\n' >/etc/systemd/system/sf-health.timer
    systemctl daemon-reload; systemctl enable --now sf-health.timer >/dev/null 2>&1
  elif [ -d /etc/periodic/hourly ]; then ln -sf "$D/health" /etc/periodic/hourly/sf-health
  elif [ -d /etc/cron.hourly ]; then ln -sf "$D/health" /etc/cron.hourly/sf-health
  else echo "no timer found: run $D/health from cron to get disk health" >&2
  fi
  "$D/health"
  command -v smartctl >/dev/null 2>&1 || echo "smartctl is not installed: install smartmontools to get SMART data" >&2
) || true
"""

UNINSTALL = r"""systemctl disable --now sf-health.timer 2>/dev/null || true
rm -f /etc/systemd/system/sf-health.service /etc/systemd/system/sf-health.timer /etc/periodic/hourly/sf-health /etc/cron.hourly/sf-health
rm -rf /var/lib/storageforge/health
"""


def install_script(group: str) -> str:
    return INSTALL.replace('@COLLECTOR@', COLLECTOR.replace('@GROUP@', group))


SCRUB_OLD_DAYS = 35
REPORT_OLD_DAYS = 3
# Attributes where anything above zero means the drive is failing or about to
BAD_ATTRS = {5: 'reallocated', 197: 'pending', 198: 'uncorrectable'}


def _smart(raw: str) -> dict | None:
    try:
        j = json.loads(raw)
    except ValueError:
        return None
    if not j.get('smart_status') and not j.get('ata_smart_attributes') and not j.get('nvme_smart_health_information_log'):
        return None                        # a USB bridge or virtual disk that answers nothing useful
    out = {'smart': 'fail' if j.get('smart_status', {}).get('passed') is False else 'ok', 'reallocated': 0, 'pending': 0, 'uncorrectable': 0,
           'temp': (j.get('temperature') or {}).get('current'), 'power_on_hours': (j.get('power_on_time') or {}).get('hours')}
    for a in (j.get('ata_smart_attributes') or {}).get('table') or []:
        if a.get('id') in BAD_ATTRS:
            out[BAD_ATTRS[a['id']]] = int((a.get('raw') or {}).get('value') or 0)
    nvme = j.get('nvme_smart_health_information_log') or {}
    out['uncorrectable'] += int(nvme.get('media_errors') or 0)
    if out['smart'] == 'ok' and (out['reallocated'] or out['pending'] or out['uncorrectable']):
        out['smart'] = 'warn'
    return out


def parse_report(text: str) -> dict | None:
    """The collector's report, small enough to keep in the inventory. None when the host has no collector."""
    if not (text or '').strip():
        return None
    out = {'at': None, 'disks': {}, 'btrfs': {}}
    head, body = None, []

    def flush():
        if not head:
            return
        kind, _, name = head.partition(' ')
        joined = '\n'.join(body)
        if kind == 'at':
            out['at'] = int(joined) if joined.strip().isdigit() else None
        elif kind == 'smart':
            if s := _smart(joined):
                out['disks'][name] = s
        elif kind == 'stats':
            out['btrfs'].setdefault(name, {})['errors'] = sum(int(m) for m in re.findall(r'\.\w+_errs\s+(\d+)', joined))
        elif kind == 'scrub':
            b = out['btrfs'].setdefault(name, {})
            started = re.search(r'Scrub started:\s*(.+)', joined)
            errs = re.search(r'Error summary:\s*(.+)', joined)
            b['last_scrub'] = started.group(1).strip() if started else None
            b['scrub_errors'] = None if not errs else 0 if 'no errors' in errs.group(1) else sum(int(x) for x in re.findall(r'=(\d+)', errs.group(1)))
        elif kind == 'snaps':
            out['btrfs'].setdefault(name, {})['snapshots'] = int(joined) if joined.strip().isdigit() else 0
    for line in text.splitlines():
        if line.startswith('## '):
            flush()
            head, body = line[3:].strip(), []
        else:
            body.append(line)
    flush()
    return out


def parse_snapshots(text: str) -> dict:
    """@@snapshots: "zfs<TAB>dataset<TAB>count<TAB>newest" and "snapper<TAB>config" lines."""
    out = {'zfs': {}, 'snapper': []}
    for line in (text or '').splitlines():
        f = line.split('\t')
        if f[0] == 'zfs' and len(f) == 4 and f[2].isdigit() and f[3].isdigit():
            out['zfs'][f[1]] = {'count': int(f[2]), 'newest': int(f[3])}
        elif f[0] == 'snapper' and len(f) == 2:
            out['snapper'].append(f[1])
    return out


def _date(text) -> dt.date | None:
    for fmt in ('%a %b %d %H:%M:%S %Y', '%Y-%m-%d %H:%M:%S'):
        try:
            return dt.datetime.strptime(' '.join(str(text).split()), fmt).date()
        except ValueError:
            pass
    return None


def zfs_scrub(scan: str | None) -> tuple[dt.date | None, int | None]:
    """(when, errors) from zpool status's scan line."""
    m = re.search(r'scrub repaired .*? with (\d+) errors? on (.+)', scan or '')
    return (_date(m.group(2)), int(m.group(1))) if m else (None, None)


def apply_report(node: dict, report: dict | None):
    """Puts health on the node's disks and last_scrub on its pools."""
    for p in node['pools']:
        if p.get('type') == 'zfs' and p.get('scan'):
            when, errors = zfs_scrub(p['scan'])
            if when:
                p.update(last_scrub=when.isoformat(), scrub_errors=errors)
    if not report:
        return
    node['health_at'] = report.get('at')
    for d in node['disks']:
        if report['disks'].get(d['dev']):
            d['health'] = report['disks'][d['dev']]
    mounts = {m.get('target'): m for m in node.get('mounts') or []}
    for target, b in report['btrfs'].items():
        src = str((mounts.get(target) or {}).get('source') or '').split('[')[0].removeprefix('/dev/')
        for p in node['pools']:
            if p.get('type', 'btrfs') == 'btrfs' and (src in (p.get('members') or []) or p.get('mount') == target or p.get('name') in (src, target)):
                when = _date(b.get('last_scrub'))
                p.update(last_scrub=when.isoformat() if when else None, scrub_errors=b.get('scrub_errors'), device_error_count=b.get('errors'))


def problems(node: dict, today: dt.date | None = None) -> list[tuple[str, str, str, str]]:
    """(level, key, title, detail) for what deserves attention. The report's findings and the alerts both use these."""
    today = today or dt.date.today()
    h, out = node['hostname'], []
    for d in node['disks']:
        s = d.get('health')
        if not s:
            continue
        bad = ', '.join(f'{s[k]} {k}' for k in ('reallocated', 'pending', 'uncorrectable') if s.get(k))
        if s['smart'] == 'fail':
            out.append(('crit', f'smart:{d["dev"]}', f'/dev/{d["dev"]} on {h} fails its SMART check', bad or 'replace it'))
        elif s['smart'] == 'warn':
            out.append(('warn', f'smart:{d["dev"]}', f'/dev/{d["dev"]} on {h} reports bad sectors', bad))
    for p in node['pools']:
        if p.get('device_error_count') or p.get('scrub_errors'):
            out.append(('crit', f'pool-errors:{p["name"]}', f'Pool {p["name"]} on {h} has errors',
                        f'{p.get("device_error_count") or 0} device errors, {p.get("scrub_errors") or 0} found by the last scrub'))
        if p.get('type') in ('zfs', 'btrfs') and (p.get('last_scrub') or node.get('health_at') or p.get('type') == 'zfs'):
            last = dt.date.fromisoformat(p['last_scrub']) if p.get('last_scrub') else None
            if not last or (today - last).days > SCRUB_OLD_DAYS:
                out.append(('warn', f'scrub:{p["name"]}', f'Pool {p["name"]} on {h} has not been scrubbed in {SCRUB_OLD_DAYS} days',
                            f'last scrub {last.isoformat()}' if last else 'no scrub on record'))
    if node.get('health_at') and time.time() - node['health_at'] > REPORT_OLD_DAYS * 86400:
        out.append(('warn', 'report-old', f'Disk health on {h} stopped updating', 'its hourly collector has not run for days'))
    return out
