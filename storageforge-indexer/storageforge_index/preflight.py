"""What a host can run, before anything is deployed on it.

    set up for deploys ──► a signed, read-only probe: the host's own answer, right now
    not set up yet     ──► what its last scan saw, plus which logins its SSH server offers

Every finding says what it means and what to do. A crit means deploys will fail there, so it stops a deploy before it
starts instead of part way through; a warn is something that often breaks a later step (a kernel with no modules for
NFS, a clock about to be refused).
"""
from __future__ import annotations

import json
import re
import subprocess
import time

from .db import loads
from .remote import child_env

# Read-only. Runs through storageforge-run, so it has bash and a root's view; each line is key=value.
PROBE = r"""export LC_ALL=C
f() { printf '%s=%s\n' "$1" "$2"; }
f os "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-}")"
f kernel "$(uname -r)"
f clock "$(date +%s)"
f init "$([ -d /run/systemd/system ] && echo systemd || echo other)"
f bash "${BASH_VERSION%%(*}"
f openssh "$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9]*\.[0-9]*\).*/\1/p')"
f sudo "$(sudo -V 2>/dev/null | sed -n '1s/^Sudo version //p')"
pm=none; for m in apt-get dnf yum zypper pacman; do command -v "$m" >/dev/null && { pm=$m; break; }; done; f pm "$pm"
se=none; [ -r /sys/fs/selinux/enforce ] && { [ "$(cat /sys/fs/selinux/enforce)" = 1 ] && se=enforcing || se=permissive; }; f selinux "$se"
fw=none; if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then fw=firewalld
elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then fw=ufw; fi; f firewall "$fw"
f modules "$([ -d "/lib/modules/$(uname -r)" ] && echo yes || echo no)"
for m in nfsd nfs cifs; do
  if grep -qw "$m" /proc/filesystems 2>/dev/null || modinfo "$m" >/dev/null 2>&1; then f "mod_$m" yes; else f "mod_$m" no; fi
done
f free_var "$(df -Pm /var 2>/dev/null | awk 'NR==2 {print $4}')"
f free_tmp "$(df -Pm /run 2>/dev/null | awk 'NR==2 {print $4}')"
have=; for c in rsync rsnapshot git exportfs smbd mount.nfs mount.cifs btrfs zfs lvs parted setcap semanage restorecon; do command -v "$c" >/dev/null && have="$have $c"; done; f have "${have# }"
f reboot "$([ -e /run/reboot-required ] && echo yes || echo no)"
"""
PROBE_LINE = re.compile(r'^(os|kernel|clock|init|bash|openssh|sudo|pm|selinux|firewall|modules|mod_\w+|free_\w+|have|reboot)=(.*)$', re.M)
OPENSSH_MIN = (8, 1)
CLOCK_REFUSED, CLOCK_WARN = 300, 60     # storageforge-run refuses a request issued 5 minutes in its future
LOW_DISK_MIB = 200


def _version(text: str | None) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r'\d+', text or '')[:2])


def parse_probe(output: str) -> dict:
    facts = {k: v.strip() for k, v in PROBE_LINE.findall(output or '')}
    facts['have'] = (facts.get('have') or '').split()
    return facts


def facts_from_scan(conn, host: str) -> dict:
    """What the last scan knows about a host: enough to tell whether it could be set up at all."""
    row = conn.all('SELECT inventory_json FROM hosts WHERE lower(hostname) = lower(:h) OR ssh_host = :h', {'h': host})
    inv = (loads(row[0][0]) or {}) if row else {}
    text = inv.get('packages') or ''
    words = [line.split(None, 1) for line in text.splitlines() if ' ' in line]
    have = [v for k, v in words if k == 'have']
    facts = {'os': (inv.get('os') or '').splitlines()[0] if inv.get('os') else '', 'have': have,
             'pm': next((v for k, v in words if k == 'pm'), 'none') if text else None}
    version = next((v for k, v in words if k == 'openssh'), None)
    if version:
        facts['openssh'] = version
    if 'init' in (k for k, _ in words):
        facts['init'] = next(v for k, v in words if k == 'init')
    if 'probed' in (k for k, _ in words):        # newer scans say which of these they looked for
        facts['bash'] = 'yes' if 'bash' in have else ''
        facts['sudo'] = 'yes' if 'sudo' in have else ''
    return facts


def findings(facts: dict, now: float | None = None) -> list[dict]:
    """[{level, text}] for what these facts mean for deploys. A fact the source could not tell is left out."""
    out = []
    say = lambda level, text: out.append({'level': level, 'text': text})   # noqa: E731
    if 'bash' in facts and not facts['bash']:
        say('crit', 'no bash: every StorageForge script needs it. Install bash, then rescan')
    if 'sudo' in facts and not facts['sudo']:
        say('crit', 'no sudo: deploys run through it. Install sudo, then rescan')
    if facts.get('init') and facts['init'] != 'systemd':
        say('crit', 'no systemd: shares, jobs and storage tasks are installed as systemd units, so they cannot run here. '
                    'Scans still work, and generated scripts can be read and adapted by hand')
    version = _version(facts.get('openssh'))
    if version and version < OPENSSH_MIN:
        say('crit', f'OpenSSH {facts["openssh"]} is too old: signed deploys need ssh-keygen -Y (8.1 or later)')
    if facts.get('pm') == 'none':
        say('warn', 'no package manager StorageForge knows (apt, dnf, yum, zypper, pacman): install what a deploy needs by hand')
    if facts.get('clock'):
        skew = int(facts['clock']) - int(now or time.time())
        if abs(skew) >= CLOCK_REFUSED:
            say('crit', f'its clock is {abs(skew)} s off: signed requests get refused. Fix the time on the host')
        elif abs(skew) >= CLOCK_WARN:
            say('warn', f'its clock is {abs(skew)} s off: signed requests are refused at 300 s')
    if facts.get('modules') == 'no':
        say('warn', f'kernel {facts.get("kernel", "")} has no modules on disk (upgraded without a reboot): NFS, SMB and other '
                    f'filesystems that are not loaded yet will not mount until it reboots')
    for mod, what in (('mod_nfsd', 'the NFS server'), ('mod_nfs', 'NFS mounts'), ('mod_cifs', 'SMB mounts')):
        if facts.get(mod) == 'no':
            say('warn', f'this kernel has no {mod[4:]} module, which {what} need. On Ubuntu it is in linux-modules-extra-$(uname -r); '
                        f'on openSUSE in kernel-default (not kernel-default-base)')
    if facts.get('reboot') == 'yes':
        say('note', 'the host is waiting for a reboot')
    for key, where in (('free_var', '/var'), ('free_tmp', '/run')):
        if facts.get(key, '').isdigit() and int(facts[key]) < LOW_DISK_MIB:
            say('warn', f'only {facts[key]} MiB free in {where}: package installs and deploy scripts need room')
    if facts.get('selinux') == 'enforcing':
        say('note', 'SELinux is enforcing: deploys set the labels they need')
    if facts.get('firewall') and facts['firewall'] != 'none':
        say('note', f'{facts["firewall"]} is active: share deploys open the ports they need')
    return out


def auth_methods(host: str, port: int = 22) -> list[str] | None:
    """The logins this SSH server offers, from its answer to a login that tries nothing. None when it can't be told.
    Nothing is sent but the key exchange and the name of a user that does not exist."""
    argv = ['ssh', '-F', '/dev/null', '-T', '-p', str(port), '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=none',
            '-o', 'ConnectTimeout=8', '-o', 'LogLevel=ERROR', f'storageforge-probe@{host}', 'true']
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15, env=child_env())
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r'Permission denied \(([^)]*)\)', p.stderr or '')
    return m.group(1).split(',') if m else None


def takes_password(methods: list[str] | None) -> bool:
    """keyboard-interactive counts: with PAM behind it, it asks for the same password."""
    return methods is None or bool({'password', 'keyboard-interactive'} & set(methods))


def blockers(conn, hosts: list[str], kind: str) -> list[dict]:
    """Hosts a deploy of this kind cannot run on, from what is known without touching them."""
    if kind not in ('shares', 'jobs', 'tasks', 'changes', 'schedules', 'clamav'):
        return []
    out = []
    for host in dict.fromkeys(hosts):
        rows = conn.all('SELECT facts_json FROM host_checks WHERE host = :h', {'h': host})
        facts = (loads(rows[0][0]) or {}) if rows else facts_from_scan(conn, host)
        for it in findings(facts):
            if it['level'] == 'crit' and (kind not in ('changes', 'schedules') or 'systemd' not in it['text']):   # change plans and cron schedules need no units
                out.append({'host': host, 'text': it['text']})
    return out


def save(conn, host: str, source: str, facts: dict, items: list[dict], actor: str | None):
    conn.execute('DELETE FROM host_checks WHERE host = :h', {'h': host})
    conn.execute("""INSERT INTO host_checks (host, source, facts_json, items_json, checked_at, checked_by)
                    VALUES (:h, :s, :f, :i, :t, :a)""",
                 {'h': host, 's': source, 'f': json.dumps(facts), 'i': json.dumps(items), 't': int(time.time()), 'a': actor})


def stored(conn) -> dict:
    """host → its last check."""
    out = {}
    for host, source, facts, items, at, by in conn.all('SELECT host, source, facts_json, items_json, checked_at, checked_by FROM host_checks'):
        out[host] = {'host': host, 'source': source, 'facts': loads(facts) or {}, 'items': loads(items) or [], 'checked_at': at, 'checked_by': by}
    return out


def host_report(db, conn, host: str, actor: str | None = None) -> dict:
    """Check one host now: by a signed probe when it is set up, else from its last scan and its SSH server's answer."""
    from . import deploy
    from .runner import connect_address
    name = deploy.canonical(conn, host)
    if deploy.ready(conn, name):
        res = deploy.run(db, name, PROBE, kind='doctor', ref=name, mode='report', actor=actor, timeout=120)
        if res['status'] != 'ok':
            items = [{'level': 'crit', 'text': f'the signed probe {res["status"]}: {res["output"].strip()[-400:] or "no output"}'}]
            save(conn, name, 'probe', {}, items, actor)
            return {'host': name, 'source': 'probe', 'facts': {}, 'items': items, 'deployable': False, 'checked_at': int(time.time())}
        facts, source = parse_probe(res['output']), 'probe'
    else:
        facts, source = facts_from_scan(conn, name), 'scan'
    items = findings(facts)
    report = {'host': name, 'source': source, 'facts': facts, 'items': items, 'checked_at': int(time.time())}
    if source == 'scan':
        port = conn.scalar('SELECT ssh_port FROM hosts WHERE hostname = :h', {'h': name}) or 22
        methods = auth_methods(connect_address(conn, name), port)
        report['ssh_logins'] = methods
        if not takes_password(methods):
            items.append({'level': 'note', 'text': 'this host takes no SSH passwords: to set it up, pick a vault key for the admin '
                                                   'account, or run the setup script as root yourself'})
    report['deployable'] = not any(i['level'] == 'crit' for i in items)
    save(conn, name, source, facts, items, actor)
    return report
