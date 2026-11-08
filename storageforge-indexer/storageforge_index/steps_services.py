"""The services a host starts, from its scan, and the `services` plan step that starts the same ones on a copy of it.

A scan records the init system and what it enables: systemd service, socket, timer and path units, or OpenRC services
by runlevel. The step enables and starts on the target what the source enables and the target has: it never disables,
never unmasks, and lists a unit the target lacks rather than installing anything (the packages step does that first).

Some units are never carried, because they belong to the machine and not to what it does: the base system's own
(systemd's, cloud-init's, the gettys), the network stack, guest tools, and StorageForge's own job and task timers,
which a deploy writes again. On a test copy timers are left out, and so is anything that sends data off the machine
(backups, sync, mail), so a copy cannot write to the source's backup targets or mail as it (docs/host-migration.md).
"""
from __future__ import annotations

import base64
import re
import shlex

from . import changes
from .changes import F

UNIT = re.compile(r'[A-Za-z0-9:_.@-]{1,200}\.(service|socket|timer|path)')
SERVICE = re.compile(r'[A-Za-z0-9_.@-]{1,100}')
RUNLEVEL = re.compile(r'[a-z0-9_-]{1,32}')
NEVER = [  # (pattern, why): the machine's own, not what it does
    (r'(systemd-|dbus|polkit|udisks|getty@|serial-getty@|autovt@|console-|kbd|keyboard-setup|setvtrgb)', 'the base system starts it'),
    (r'(cloud-|ds-identify|pollinate|jeos-|combustion|ignition|afterburn)', 'first-boot setup belongs to the target'),
    (r'(NetworkManager|networking(\.|$)|wicked|networkd-dispatcher|dhcpcd|connman|iwd|wpa_supplicant|netplan)', 'the target keeps its own network setup'),
    (r'(qemu-guest-agent|spice-vdagent|open-vm-tools|vmtoolsd|vgauth|lxd-agent|hv-|hyperv|waagent|google-|amazon-ssm|xe-)', 'guest tools belong to the target'),
    (r'(sf-job-|sf-task-|storageforge)', 'a StorageForge deploy writes it again'),
    (r'(ufw|firewalld|nftables|iptables|ip6tables|netfilter-persistent|shorewall|ferm)(\.|$)',
     'a firewall without its rules could shut out SSH: the firewall comes across with its rules, through the network plans'),
    (r'(grub-|secureboot-|finalrd|shim-|ua-|ubuntu-advantage|ubuntu-pro|rhsmcertd|insights-client|SuSEConnect)', 'boot and subscriptions belong to the target'),
    (r'snap\.', 'snapd makes it for each snap the packages step installs'),
]
# OpenRC runlevels the base system fills: only default and the operator's own come across
BASE_RUNLEVELS = ('sysinit', 'boot', 'shutdown', 'nonetwork')
OUTWARD = (r'(rsnapshot|borg|borgmatic|restic|rclone|syncoid|zrepl|znapzend|duplicati|duplicity|syncthing|unison|lsyncd|'
           r'urbackup|bacula|bareos|amanda|kopia|duplicacy|postfix|exim|sendmail|msmtp|nullmailer|ssmtp|opensmtpd|fetchmail|offlineimap)')
SKIP = [(re.compile(p), why) for p, why in NEVER]
SENDS = re.compile(OUTWARD)


def parse(text: str) -> dict:
    """{init, enabled: [{unit, preset}]} for systemd, {init, enabled: [{unit, runlevel}]} for OpenRC; None for neither."""
    init, enabled = None, []
    for line in (text or '').splitlines():
        if line.startswith('init '):
            init = line[5:].strip() if line[5:].strip() in ('systemd', 'openrc') else None
            continue
        kind, _, rest = line.partition('\t')
        a, _, b = rest.partition('\t')
        if kind == 'e' and UNIT.fullmatch(a):
            enabled.append({'unit': a, 'preset': b.strip() if b.strip() in ('enabled', 'disabled', 'ignored') else None})
        elif kind == 'o' and SERVICE.fullmatch(a) and RUNLEVEL.fullmatch(b.strip()):
            enabled.append({'unit': a, 'runlevel': b.strip()})
    return {'init': init, 'enabled': enabled} if init else None


def for_host(conn, host: str) -> dict | None:
    from .db import loads
    raw = conn.scalar('SELECT inventory_json FROM hosts WHERE lower(hostname) = lower(:h)', {'h': host})
    return ((loads(raw) or {}) if raw else {}).get('services')


def choose(sv: dict | None, timers: bool) -> tuple[list[dict], list[tuple[str, str]]]:
    """What to start on the copy, and what is left out with why."""
    take, left = [], []
    for e in (sv or {}).get('enabled') or []:
        u = e['unit']
        why = next((w for p, w in SKIP if p.match(u)), None)
        if not why and e.get('runlevel') in BASE_RUNLEVELS:
            why = f'the {e["runlevel"]} runlevel belongs to the base system'
        if not why and not timers and u.endswith('.timer'):
            why = 'a timer: on a test copy, timers stay off'
        if not why and not timers and SENDS.match(u):
            why = 'it sends data off the machine: on a test copy it stays off'
        (left.append((u, why)) if why else take.append(e))
    return take, left


def _b64(lines: list[str]) -> str:
    return base64.b64encode(('\n'.join(lines) + '\n').encode()).decode() if lines else ''


def _args(conn, t):
    sv = for_host(conn, t['params']['from_host'])
    take, left = choose(sv, bool(t['params'].get('timers')))
    rows = [e['unit'] + ('\t' + e['runlevel'] if e.get('runlevel') else '') for e in take]
    return [(sv or {}).get('init') or '', _b64(rows), _b64([f'{u}\t{why}' for u, why in left])]


# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
t_services() { local from=$1 timers=$2 init=$3 want=$4 left=$5 here u lvl st n=0 have=0 gone=0 why
  if [[ -d /run/systemd/system ]]; then here=systemd; elif command -v rc-update >/dev/null; then here=openrc; else here=unknown; fi
  [[ -n $init ]] || { conflict "$from has no list of services: scan it again with this version"; return 0; }
  [[ $here == "$init" ]] || { conflict "$from starts its services with $init and this host with $here: nothing is enabled"; return 0; }
  while IFS=$'\t' read -r u why || [[ -n ${u:-} ]]; do [[ -n $u ]] && skip "$u: $why"; done < <(printf %s "$left" | base64 -d)
  while IFS=$'\t' read -r u lvl || [[ -n ${u:-} ]]; do
    [[ -n $u ]] || continue
    n=$((n + 1))
    if [[ $init == systemd ]]; then
      st=$(systemctl is-enabled -- "$u" 2>/dev/null || true)
      case $st in
        enabled|enabled-runtime|alias) have=$((have + 1)) ;;
        static|indirect|generated|transient) ok "$u is $st: nothing to enable" ;;
        masked|masked-runtime) conflict "$u is masked here: left as it is" ;;
        disabled)
          act "systemctl enable $u, and start it" || continue
          if ! systemctl enable -- "$u" >/dev/null 2>&1; then conflict "systemctl enable $u failed"; continue; fi
          if systemctl start -- "$u" 2>/dev/null; then ok "$u enabled and started"
          else conflict "$u is enabled, and did not start: $(journalctl -u "$u" -n 1 --no-pager -o cat 2>/dev/null | tail -n 1)"; fi ;;
        *) gone=$((gone + 1)); missing "$u is not here: install its package, then run this again" ;;
      esac
    else
      if [[ ! -e /etc/init.d/$u ]]; then gone=$((gone + 1)); missing "$u is not here: install its package, then run this again"; continue; fi
      if rc-update show "$lvl" 2>/dev/null | awk -F"|" -v s="$u" "{gsub(/ /, \"\", \$1)} \$1 == s {f = 1} END {exit !f}"; then have=$((have + 1)); continue; fi
      act "rc-update add $u $lvl, and start it" || continue
      if ! rc-update add "$u" "$lvl" >/dev/null 2>&1; then conflict "rc-update add $u $lvl failed"; continue; fi
      if rc-service "$u" start >/dev/null 2>&1; then ok "$u added to $lvl and started"; else conflict "$u is added to $lvl, and did not start"; fi
    fi
  done < <(printf %s "$want" | base64 -d)
  ok "$have of $n already enabled here, as on $from"
  ((gone)) && info "$gone not installed here: the packages step comes first in a copy"
  return 0
}
"""


def _check(conn, c, h, p, say):
    sv = for_host(conn, p['from_host'])
    if not sv:
        say('crit', f'{p["from_host"]} has no list of services: scan it again with this version')
        return
    mine = for_host(conn, h['name'])
    if mine and mine['init'] != sv['init']:
        say('crit', f'{p["from_host"]} uses {sv["init"]} and {h["name"]} {mine["init"]}: nothing can be enabled')
        return
    take, left = choose(sv, bool(p.get('timers')))
    already = {e['unit'] for e in (mine or {}).get('enabled') or []}
    new = [e['unit'] for e in take if e['unit'] not in already]
    say('note', f'{len(new)} to enable and start' + (f': {", ".join(new[:12])}' + (' …' if len(new) > 12 else '') if new else '')
        + f'; {len(take) - len(new)} already enabled here')
    if left:
        say('note', f'{len(left)} left out: ' + '; '.join(f'{u} ({why})' for u, why in left[:6]) + (' …' if len(left) > 6 else ''))
    say('note', 'never disables or unmasks a unit, and never installs one: a unit not installed here is listed')


def _ansible(t, conn):
    q = shlex.quote
    p = t['params']
    extra = _args(conn, t) if conn is not None else ['', '', '']
    head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; }; info() { :; }; skip() { :; }\n'
            'act() { echo "changed: $*"; }\n')
    call = ' '.join(q(a) for a in [p['from_host'], '1' if p.get('timers') else '', *extra])
    return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + BASH + f'\nt_services {call}\n', 'executable': '/bin/bash'},
            'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}


changes.register('services', {'group': 'Software', 'label': 'Start the services of another host', 'fields': [
    F('from_host', 'host', 'The services of', required=True, placeholder='web-01'),
    F('timers', 'bool', 'Timers, backups and mail too (a migration, not a test copy)')],
    'help': 'Enables and starts here what that host enables, from its last scan. Never disables or unmasks anything, and lists a unit '
            'that is not installed here. The base system, network setup, guest tools and StorageForge jobs are always left out.'},
    ('from_host', 'timers'), lambda p: f'Services of {p["from_host"]}', _check, _ansible, args_of=_args)
changes.EXTRA_BASH.append(BASH)
