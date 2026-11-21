#!/usr/bin/env python3
"""Tier 14 of the KVM lab: host logs (hostlogs.py) against real journald on real distros.

First run on 2026-11-08. The checks named `caps` and `logrule-*` were rewritten or added for 0.5.4 (what is kept goes by arrival; a rate
per host; log rules), and have not run until a lab run after that says so.

What a stand-in journalctl cannot say, and this tier is for:

    read       a scan user in the systemd-journal group reads the whole journal: the line written on the VM comes back with its level
               and identifier, and /api/hostlogs/counts and /units agree with what the VM's own journalctl lists
    limited    the same user outside the group is told so, and nothing is stored; the access script adds the group, and the next
               scan reads back the line written while it could not
    no journal a host without journald says so (sf-alpine, the one config with no systemd) and stores nothing
    secrets    a line holding password=hunter2, written with logger on the VM, is stored with the secret removed, in the table and not
               only in the API's answer
    caps       what is kept of real journal text read from the VM, by the product's own store(): every line on arrival however old its
               stamp, gone 31 days after it arrived and not before, 50 at a row limit of 50, and at a rate of 20 a day the warnings
               first with the rest recorded as over and still counted. In a throwaway database inside the sf-ctl container, with the
               clock moved on, because the real limits can't be waited for or filled in a lab run
    logrule    the built-in log rules against what a real kernel logs when storage really fails: an md array with a member failed, a
               device that returns I/O errors (dm-error), a ZFS pool with a disk taken offline. Each is one critical notification for
               that host that cannot be snoozed. A flood of one line is one notification that says how many, and `logger -t sshd`
               does not set off the rule about sshd

For 0.5.8 (section 3, phases 3 to 5), written and not run yet:

    anomalies  real journal text from the VM, laid over three weeks before now in a throwaway database, through the product's own
               store and loganomaly: an ordinary hour says nothing, the shapes of real lines are fewer than the lines, and 600 lines
               of a flood with one line of a kind never logged are a volume warning and a new kind with that line as its sample
    monitor    /api/hostlogs/monitor on the real controller lists every host, and each one's ingest says what /api/hostlogs/status says
    netconsole the netconsole plan step deployed on a lab host: the file it writes names the controller, netconsole is loaded, a line
               written to /dev/kmsg on the VM comes back over UDP with its level and marked not signed, and the way back takes it
               all out so the next line does not come. Needs the controller listening (compose.lab.yml sets it)
    panic      only with SFLAB_CRASH=1, on the throwaway UEFI VM: netconsole set up by the step's own script, the kernel crashed with
               sysrq, the panic seen over netconsole and raised as critical, and after the VM reboots by itself the scan finds the
               crash record in pstore

A check reads the answer from the VM it is about, never from StorageForge's report of its work. tiers.py runs it.
"""
import json
import os
import re
import secrets
import shlex
import time

import demo
import roles
from demo import COMPOSE, ssh

import tiers as t
from tiers_platform import sudo

TAG = 'sflab-hostlog'
GROUPS_THAT_READ = {'systemd-journal', 'adm', 'wheel', 'root'}      # hostlogs.JOURNAL_GROUPS


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def in_product(code, *args, stdin=None, env=()):
    """Python in the running StorageForge container: the product's own code, on a throwaway database where the check says so."""
    flags = ' '.join(f'-e {shlex.quote(e)}' for e in env)
    return ssh('sf-ctl', f'{COMPOSE} exec -T {flags} storageforge python -c {shlex.quote(code)} {shlex.join(args)}', stdin=stdin)


def groups_of(vm, user='scan'):
    return set(sudo(vm, f'id -nG {user}').split())


def write_line(vm, text, priority='user.err', tag=TAG):
    """One line into the VM's journal, with logger, or systemd-cat where there is no logger."""
    q = shlex.quote
    sudo(vm, f'if command -v logger >/dev/null 2>&1; then logger -t {q(tag)} -p {q(priority)} -- {q(text)}; '
             f'else printf "%s\\n" {q(text)} | systemd-cat -t {q(tag)} -p {q(priority.split(".")[-1])}; fi')


def status(api, name):
    got = api.get(f'/api/hostlogs/status?host={name}')['hosts']
    return got[0] if got else None


def entries(api, name, q, limit=50):
    got = api.get(f'/api/hostlogs?host={name}&q={q}&limit={limit}')['entries']
    return [e for e in got if e.get('ident') == TAG]      # sudo logs the command that wrote the line, marker and all, so its own line matches the search too


def stored_rows(name):
    return t.sql(f"SELECT count(*) n FROM host_log_lines WHERE host = '{name}'")[0]['n']


def scan(api, node):
    demo.scan(api, [node.ip])


def tier14(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)          # the prepared fix is deployed as a change plan
    nodes = list(roles.build().values())
    journald = [n for n in nodes if not n.can('nosystemd')]
    bare = [n for n in nodes if n.can('nosystemd')]
    state = {}

    # ── a host with no journald ─────────────────────────────────
    def no_journal(node):
        def check():
            want(ssh(node.name, 'command -v journalctl >/dev/null 2>&1 && echo yes || echo no').strip() == 'no', f'{node.name} has journalctl: this check would prove nothing')
            scan(api, node)
            got = status(api, node.name)
            want(got and got['state'] == 'no_journal', f'its status: {got}')
            want('no journalctl' in got['note'], f'the note does not say why: {got["note"]!r}')
            want(stored_rows(node.name) == 0 and got['lines'] == 0, 'lines were stored for a host with no journal')
            counts = api.get(f'/api/hostlogs/counts?host={node.name}')
            want(counts['total'] == 0 and counts['by_hour'] == [] and api.get(f'/api/hostlogs/units?host={node.name}')['units'] == [], f'counts or units invented something: {counts}')
            return f'"{got["note"]}"'
        return check
    for node in bare:
        r.check('hostlogs-no-journald', node.name, no_journal(node))
    if not bare:
        r.add('hostlogs-no-journald', '-', None, 'no host without systemd in this build')

    # ── outside the group, then in it ───────────────────────────
    def limited(node):
        def check():
            sudo(node.name, 'gpasswd -d scan systemd-journal 2>/dev/null; true')
            want(not groups_of(node.name) & GROUPS_THAT_READ, f'scan is still in {groups_of(node.name)}')
            state[node.name] = secrets.token_hex(6)
            write_line(node.name, f'written while the scan user could not read {state[node.name]}')
            before = stored_rows(node.name)
            scan(api, node)
            got = status(api, node.name)
            want(got and got['state'] == 'limited', f'its status: {got}')
            want('access script' in got['note'], f'the note does not say what to do: {got["note"]!r}')
            want(stored_rows(node.name) == before, 'lines were stored from a journal the scan user could only partly read')
            return 'told to run the access script, and nothing stored'
        return check

    def reads(node):
        def check():
            script = api.get('/api/access/script?user=scan')['script']
            ssh(node.name, 'sudo -n sh -s', stdin=script)
            want(groups_of(node.name) & GROUPS_THAT_READ, f'the access script left scan in {groups_of(node.name)}')
            marker = secrets.token_hex(6)
            started = int(sudo(node.name, 'date +%s'))
            write_line(node.name, f'journal read check {marker}', 'user.err')
            write_line(node.name, f'journal read check warn {marker}', 'user.warning')
            scan(api, node)
            got = status(api, node.name)
            want(got and got['state'] == 'ok' and got['lines'] > 0, f'its status: {got}')
            found = entries(api, node.name, marker)
            want(len(found) == 2, f'the two lines written on the VM: {found}')
            by_level = {e['level']: e for e in found}
            want({'err', 'warning'} <= set(by_level), f'levels: {sorted(by_level)}')
            want(all(e['ident'] == TAG for e in found), f'identifiers: {[e["ident"] for e in found]}')
            want(all(started - 5 <= e['ts'] <= time.time() + 5 for e in found), f'times: {[e["ts"] for e in found]}')
            # what the scan left behind while it could not read: read back on the first scan with access
            if node.name in state:
                back = entries(api, node.name, state[node.name])
                want(len(back) == 1, f'the line written before access was not read back: {back}')

            # counts and units, against the VM's own journal
            counts = api.get(f'/api/hostlogs/counts?host={node.name}')
            want(counts['total'] == got['lines'] == sum(counts['by_level'].values()), f'counts {counts["total"]}, kept {got["lines"]}')
            want(counts['by_level']['err'] >= 1 and counts['by_level']['warning'] >= 1, f'by level: {counts["by_level"]}')
            want(sum(h['total'] for h in counts['by_hour']) == counts['total'] and all(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:00:00Z', h['hour']) for h in counts['by_hour']),
                 f'by hour: {counts["by_hour"][:3]}')
            want([h['hour'] for h in counts['by_hour']] == sorted(h['hour'] for h in counts['by_hour']), 'the hours are not in order')
            narrow = api.get(f'/api/hostlogs/counts?host={node.name}&since={started - 5}&until={int(time.time()) + 5}')
            want(2 <= narrow['total'] <= counts['total'], f'a range around the two lines: {narrow["total"]} of {counts["total"]}')
            code, body = api.raw('GET', f'/api/hostlogs/counts?host={node.name}&since={started + 100}&until={started}')
            want(code == 400, f'since after until was not refused: {code} {body}')
            listed = api.get(f'/api/hostlogs/units?host={node.name}')['units']
            real = {x.strip() for x in sudo(node.name, 'journalctl -F _SYSTEMD_UNIT --no-pager', check=False).splitlines()}
            want(listed and len(listed) <= 200, f'units: {len(listed)}')
            want([u['lines'] for u in listed] == sorted((u['lines'] for u in listed), reverse=True), 'units are not most-lines first')
            unknown = [u['unit'] for u in listed if u['unit'] not in real]
            want(not unknown, f'units the VM\'s journal has never heard of: {unknown[:5]}')
            return f'{got["lines"]} lines kept, the err and warning lines back with their identifier, {len(listed)} unit(s), counts add up'
        return check

    for node in journald:
        if groups_of(node.name) & {'adm', 'wheel'}:          # this distro's scan user reads the journal by another group: no limit to show
            r.add('hostlogs-limited', node.name, None, f'scan is in {sorted(groups_of(node.name))} already')
        else:
            r.check('hostlogs-limited', node.name, limited(node))
        r.check('hostlogs-read', node.name, reads(node))
    if not journald:
        r.add('hostlogs-read', '-', None, 'no host with systemd in this build')

    # ── secrets, on real lines ──────────────────────────────────
    def secret_removed(node):
        def check():
            marker = secrets.token_hex(6)
            lines = [f'login failed for gabe password=hunter2 {marker}', f'curl https://bob:hunter2@example.com/x {marker}', f'deploy --api-key=hunter2 Authorization: Bearer hunter2hunter2 {marker}']
            for line in lines:
                write_line(node.name, line, 'user.notice')
            on_vm = ssh(node.name, f'sudo -n journalctl -t {TAG} -o cat --no-pager -n 20')
            want(marker in on_vm and 'hunter2' in on_vm, 'the journal on the VM does not hold the secret: this would prove nothing')
            scan(api, node)
            found = entries(api, node.name, marker)
            want(len(found) == len(lines), f'lines read back: {len(found)} of {len(lines)}')
            for e in found:
                want('hunter2' not in e['message'] and '[redacted]' in e['message'], f'stored as {e["message"]!r}')
                want(marker in e['message'], 'the rest of the line was lost along with the secret')
            held = t.sql(f"SELECT count(*) n FROM host_log_lines WHERE host = '{node.name}' AND message LIKE '%hunter2%'")[0]['n']
            want(held == 0, f'{held} row(s) in the table hold the secret')
            exported = api.text(f'/api/hostlogs/export?host={node.name}&q={marker}&format=json')
            want('hunter2' not in exported, 'the export holds the secret')
            return 'password=, a URL password, an API key and a bearer token removed; the line around them kept; none in the table or the export'
        return check
    for node in journald:
        r.check('hostlogs-secrets-removed', node.name, secret_removed(node))

    # ── what is kept, on real journal text: by arrival, a row limit, and a rate ─────────
    fetch = 'from storageforge_index import hostlogs; import sys; print(hostlogs.script(int(sys.argv[1])))'
    caps = '''
import json, os, shutil, sys, tempfile, time
from storageforge_index import hostlogs
from storageforge_index.db import Database
text, now = sys.stdin.read(), time.time()
hostlogs.RATE_PER_DAY = float(os.environ.get('LAB_RATE', '1000000'))
out = {'keep_days': hostlogs.KEEP_DAYS, 'keep_rows': hostlogs.KEEP_ROWS, 'first_days': hostlogs.FIRST_DAYS}
d = tempfile.mkdtemp(); db = Database(d + '/t.db'); conn = db.connect(); db.migrate(conn)
count = lambda where='': conn.scalar('SELECT count(*) FROM host_log_lines WHERE host = :h' + where, {'h': 'h'})
parsed = hostlogs.parse(text, now)
hostlogs.store(conn, 'h', parsed, now)
st = hostlogs.status(conn, 'h')[0]
stamps = [x['at_us'] / 1e6 for x in parsed['lines']]
out['first'] = {'read': len(parsed['lines']), 'kept': count(), 'state': parsed['state'], 'over': st['over_rate'], 'oldest_days': (now - min(stamps)) / 86400 if stamps else 0,
                'worst_kept': conn.scalar('SELECT max(priority) FROM host_log_lines'), 'warnings_read': sum(x['priority'] <= 4 for x in parsed['lines']),
                'warnings_kept': count(' AND priority <= 4'), 'counted': conn.scalar('SELECT sum(lines) FROM host_log_counts'),
                'journald_fields': count(' AND comm IS NOT NULL AND uid IS NOT NULL'), 'seqnums': count(' AND seqnum IS NOT NULL')}
def later(days, word):
    at = now + days * 86400
    line = {'key': word, 'at_us': int((at - 5) * 1e6), 'priority': 6, 'unit': None, 'ident': 'lab', 'pid': None, 'message': word}
    hostlogs.store(conn, 'h', {'lines': [line], 'state': 'ok', 'cut': False}, at)
    return {'kept_of_first': count(" AND message <> 'later-a' AND message <> 'later-b'"), 'kept': count()}
out['day29'] = later(hostlogs.KEEP_DAYS - 1, 'later-a')
out['day31'] = later(hostlogs.KEEP_DAYS + 1, 'later-b')
conn.close(); shutil.rmtree(d, True)      # the container's temp space is small
print(json.dumps(out))
'''

    def limits(node):
        def check():
            sudo(node.name, f'for i in $(seq 1 150); do logger -t {TAG}-fill -p user.notice "fill line $i"; done; for i in 1 2 3; do logger -t {TAG}-fill -p user.warning "fill warning $i"; done')
            since = int(time.time()) - 7 * 86400
            text = ssh(node.name, 'sudo -n -u scan sh -s', stdin=in_product(fetch, str(since)))
            want('@@who' in text and '@@end' in text, f'the collection script did not run to its end on {node.name}: {text[-300:]}')
            all_kept = json.loads(in_product(caps, stdin=text, env=['STORAGEFORGE_LOG_KEEP_ROWS=500000', 'STORAGEFORGE_LOG_KEEP_DAYS=30']))
            want(all_kept['keep_days'] == 30 and all_kept['first_days'] == 7, f'the limits: {all_kept}')
            first = all_kept['first']
            want(first['state'] == 'ok' and first['read'] > 150, f'the VM gave {first["read"]} lines: not enough to test with')
            want(first['kept'] == first['read'] and first['over'] == 0, f'lines were dropped as they were stored, though the oldest is {first["oldest_days"]:.1f} days old: {first}')
            want(first['counted'] == first['read'], f'the 5-minute counts hold {first["counted"]} of {first["read"]} lines')
            want(first['journald_fields'] > 0, 'no line has journald\'s own _COMM and _UID: the script asked for them and this journalctl gave none')
            want(all_kept['day29']['kept_of_first'] == first['read'], f'lines were dropped {30 - 1} days after they arrived: {all_kept["day29"]}')
            # two: the line that arrived on day 29 is two days old by day 31, and the one that arrived then
            want(all_kept['day31'] == {'kept_of_first': 0, 'kept': 2}, f'31 days after they arrived the first lines should be gone and the two that arrived since kept: {all_kept["day31"]}')
            row_cap = json.loads(in_product(caps, stdin=text, env=['STORAGEFORGE_LOG_KEEP_ROWS=50', 'STORAGEFORGE_LOG_KEEP_DAYS=30']))
            want(row_cap['keep_rows'] == 50 and row_cap['first']['kept'] == 50, f'the row limit of 50 kept {row_cap["first"]["kept"]}')
            rate = json.loads(in_product(caps, stdin=text, env=['STORAGEFORGE_LOG_KEEP_ROWS=500000', 'STORAGEFORGE_LOG_KEEP_DAYS=30', 'LAB_RATE=20']))['first']
            want(rate['kept'] == 20 and rate['over'] == rate['read'] - 20, f'a rate of 20 a day kept {rate["kept"]} and recorded {rate["over"]} over, of {rate["read"]}')
            want(rate['warnings_kept'] == min(20, rate['warnings_read']) and rate['warnings_read'] >= 3, f'the rate took warnings before routine lines: {rate}')
            want(rate['counted'] == rate['read'], f'a line over the rate was not counted: {rate}')
            return (f'{first["read"]} real lines, the oldest {first["oldest_days"]:.1f} days old: all kept on arrival, still there after 29 days, gone after 31; 50 kept at a row limit of 50; '
                    f'at a rate of 20, {rate["warnings_kept"]} warnings kept first and {rate["over"]} recorded as over and counted; journald\'s own fields on {first["journald_fields"]} lines, a sequence number on {first["seqnums"]}')
        return check
    for node in journald:
        r.check('hostlogs-caps', node.name, limits(node))

    # ── log rules, against storage that really fails (roadmap 1.4 and section 3, phase 1) ─────────
    def raised(node, builtin=None, name=None):
        """The open log-rule notifications for this host after one scan and one evaluation, as the center lists them."""
        scan(api, node)
        t.alerts_now()
        got = api.get(f'/api/notifications?host={node.name}&kind=log-rule')
        items = [x for g in got['groups'] + got['quiet'] for x in g['items']]
        rules = {x['id']: x for x in api.get('/api/hostlogs/rules')['rules']}
        out = []
        for x in items:
            rule = rules.get(int(x['key'].split(':')[1]), {})
            if (builtin is None or rule.get('builtin') == builtin) and (name is None or rule.get('name') == name):
                out.append({**x, 'rule': rule})
        return out

    def cannot_be_snoozed(item):
        code, out = api.raw('POST', f'/api/notifications/snooze/{item["key"]}', {'hours': 1})
        want(code == 400 and 'cannot be snoozed' in out.get('error', ''), f'a critical notification was snoozed: {code} {out}')

    def md_degraded(node):
        def check():
            sudo(node.name, 'command -v mdadm >/dev/null || { if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get -qq update; DEBIAN_FRONTEND=noninteractive apt-get -qq install -y mdadm; '
                            'elif command -v dnf >/dev/null; then dnf -q -y install mdadm; else zypper -nq install mdadm; fi; }; command -v mdadm >/dev/null')
            sudo(node.name, 'set -e; cd /var/tmp; for i in 1 2; do truncate -s 64M sflab-md$i.img; done; a=$(losetup --find --show sflab-md1.img); b=$(losetup --find --show sflab-md2.img); '
                            'mdadm --create /dev/md/sflab --run --level=1 --raid-devices=2 --metadata=1.2 "$a" "$b" >/dev/null 2>&1; sleep 2; mdadm /dev/md/sflab --fail "$b" >/dev/null 2>&1; sleep 2; echo "$a $b" > sflab-md.loops')
            try:
                said = sudo(node.name, 'journalctl -k -b --no-pager -o cat | grep -i "md/raid1\\|Operation continuing" | tail -3').strip()
                want(said, 'the kernel logged nothing about the failed member: this would prove nothing')
                got = raised(node, 'pool-degraded')
                want(len(got) == 1, f'the kernel said {said!r}, and the rule raised {len(got)} notification(s)')
                want(got[0]['level'] == 'crit' and not got[0]['ignorable'], f'it should be critical and not ignorable: {got[0]}')
                cannot_be_snoozed(got[0])
                return f'{said.splitlines()[-1][:90]!r}: one critical notification, which cannot be snoozed'
            finally:
                sudo(node.name, 'cd /var/tmp; mdadm --stop /dev/md/sflab >/dev/null 2>&1; for l in $(cat sflab-md.loops 2>/dev/null); do losetup -d $l 2>/dev/null; done; rm -f sflab-md*.img sflab-md.loops; true', check=False)
        return check

    def io_error(node):
        def check():
            sudo(node.name, 'set -e; cd /var/tmp; truncate -s 16M sflab-err.img; l=$(losetup --find --show sflab-err.img); echo $l > sflab-err.loop; '
                            'echo "0 $(blockdev --getsz $l) error" | dmsetup create sflab-err; dd if=/dev/mapper/sflab-err of=/dev/null bs=4k count=4 iflag=direct 2>/dev/null || true; sleep 1')
            try:
                said = sudo(node.name, 'journalctl -k -b --no-pager -o cat | grep -i "I/O error" | tail -2').strip()
                want(said, 'the kernel logged no I/O error for a device that returns only errors: this would prove nothing')
                got = raised(node, 'io-error')
                want(len(got) == 1 and got[0]['level'] == 'crit', f'the kernel said {said!r}, and the rule raised {got}')
                return f'{said.splitlines()[-1][:90]!r}: one critical notification'
            finally:
                sudo(node.name, 'cd /var/tmp; dmsetup remove sflab-err 2>/dev/null; losetup -d $(cat sflab-err.loop 2>/dev/null) 2>/dev/null; rm -f sflab-err.img sflab-err.loop; true', check=False)
        return check

    def zfs_offline(node):
        def check():
            pool = node.tag('zfs-pool')
            disk = sudo(node.name, f"zpool status -P {pool} | awk '$1 ~ /^\\/dev\\// {{print $1}}' | tail -1").strip()
            want(disk, f'no disk found in {pool}')
            sudo(node.name, f'zpool offline {pool} {disk}; sleep 4')
            try:
                want('DEGRADED' in sudo(node.name, f'zpool status {pool}'), f'{pool} is not degraded with {disk} offline: this would prove nothing')
                said = sudo(node.name, 'journalctl -b --no-pager -o cat --since "-2 min" -t zed -t kernel | grep -i "statechange\\|degraded\\|offline" | tail -3', check=False).strip()
                got = raised(node, 'pool-degraded')
                want(got, f'{pool} is degraded and the rule raised nothing. What the host logged about it: {said or "nothing: a pool taken offline by hand may log only through zed"}')
                # the md check may have raised this rule on this host already: it has to be the pool's own line that the rule last saw
                want(pool in got[0]['message'] or 'statechange' in got[0]['message'] or 'vdev' in got[0]['message'], f'the rule is open, but not for {pool}: {got[0]["message"]!r}. What the host logged: {said!r}')
                return f'{pool} degraded: {got[0]["message"][-110:]!r}: {got[0]["level"]}'
            finally:
                sudo(node.name, f'zpool online {pool} {disk}; zpool clear {pool}; true', check=False)
        return check

    def flood_is_one(node):
        def check():
            sudo(node.name, 'for i in $(seq 1 60); do logger -t rsync -p daemon.err "rsync: write failed on /srv/x$i: No space left on device (28)"; done')
            got = raised(node, 'disk-full')
            want(len(got) == 1, f'60 lines raised {len(got)} notification(s)')
            want('60 line(s)' in got[0]['message'] and got[0]['level'] == 'warn', f'it should say how many and be a warning: {got[0]["message"]!r}')
            return 'sixty lines, one warning that says sixty'
        return check

    def program_is_journalds(node):
        def check():
            rule = next(x for x in api.get('/api/hostlogs/rules')['rules'] if x['builtin'] == 'ssh-failed')
            api('PUT', f'/api/hostlogs/rules/{rule["id"]}', {**rule, 'enabled': True})
            try:
                sudo(node.name, 'for i in $(seq 1 30); do logger -t sshd -p auth.info "Failed password for root from 203.0.113.9 port $i ssh2"; done')
                got = raised(node, 'ssh-failed')
                found = [e for e in api.get(f'/api/hostlogs?host={node.name}&q=203.0.113.9&limit=40')['entries'] if e['message'].startswith('Failed password')]      # not sudo's own line about the command
                want(found and found[0]['comm'] == 'logger' and found[0]['ident'] == 'sshd', f'the lines should be stored as written by logger under the name sshd: {found[:1]}')
                want(not got, f'thirty lines that logger wrote under the name sshd set off the rule about sshd: {got}')
                return 'thirty lines under the name sshd, written by logger as journald saw: stored as such, and the rule about sshd did not fire'
            finally:
                api('PUT', f'/api/hostlogs/rules/{rule["id"]}', {**rule, 'enabled': False})
        return check

    def fix_and_back(node):
        """Section 12's lab line: a failed unit fixed on a lab host, prepared, deployed, rolled back; and no fix where there is no way back."""
        def check():
            unit = 'sflab-fails.service'
            sudo(node.name, f"printf '%s\\n' '[Service]' 'ExecStart=/bin/sh -c \"test -e /run/sflab-cured && exec sleep infinity\"' > /etc/systemd/system/{unit}; systemctl daemon-reload; "
                            f'for i in 1 2 3; do systemctl start {unit} 2>/dev/null; sleep 1; done; true')
            try:
                want(sudo(node.name, f'systemctl is-active {unit}; true').strip() == 'failed', 'the unit did not fail: this would prove nothing')
                got = raised(node, 'unit-failed')
                want(len(got) == 1, f'three failures raised {len(got)} notification(s)')
                item = got[0]
                want(item['fix'] and item['fix']['label'] == f'Restart {unit} on {node.name}', f'the fix it offers: {item["fix"]}')
                others = [x for g in api.get('/api/notifications')['groups'] for x in g['items'] if x['kind'] in ('scan-failed', 'job-stale', 'disk-crit', 'disk-warn', 'drift')]
                want(all(x['fix'] is None for x in others), f'a fix was offered where there is no way back: {[x["title"] for x in others if x["fix"]]}')
                sudo(node.name, 'touch /run/sflab-cured')            # what made it fail is put right: a restart can work now
                plan = api.post(f'/api/notifications/fix/{item["key"]}')['plan']
                want(sudo(node.name, f'systemctl is-active {unit}; true').strip() == 'failed', 'preparing the fix changed the host')
                demo.deploy(api, 'changes', plan, 'the prepared fix')
                want(sudo(node.name, f'systemctl is-active {unit}; true').strip() == 'active', 'the deployed fix did not start the unit')
                undo = api.post(f'/api/notifications/undo/{plan}')['plan']
                demo.deploy(api, 'changes', undo, 'the way back')
                state = sudo(node.name, f'systemctl is-active {unit}; true').strip()
                want(state == 'inactive', f'the way back left the unit {state}')
                want(sudo(node.name, f'systemctl is-enabled {unit} 2>/dev/null; true').strip() in ('static', 'disabled', ''), 'the fix enabled the unit')
                return f'{unit} failed three times: one notification with a fix; prepared (nothing changed), deployed (running), its way back deployed (stopped); no fix offered on {len(others)} other notification(s)'
            finally:
                sudo(node.name, f'systemctl stop {unit} 2>/dev/null; rm -f /etc/systemd/system/{unit} /run/sflab-cured; systemctl daemon-reload; systemctl reset-failed {unit} 2>/dev/null; true', check=False)
        return check

    able = [n for n in journald if n.can('deploy') and not n.can('controller')]
    if able:
        r.check('logrule-md-degraded', able[0].name, md_degraded(able[0]))
        r.check('logrule-io-error', able[-1].name, io_error(able[-1]))
        r.check('logrule-flood-is-one', able[0].name, flood_is_one(able[0]))
        r.check('logrule-program', able[-1].name, program_is_journalds(able[-1]))
        r.check('notify-fix-and-back', able[0].name, fix_and_back(able[0]))
    else:
        r.add('logrule-md-degraded', '-', None, 'no host with systemd that deploys in this build')
    pools = [n for n in journald if n.can('zfs') and able and n.name != able[0].name] or [n for n in journald if n.can('zfs')]      # not the host the md check degraded, where there is another
    if pools:
        r.check('logrule-zfs-offline', pools[0].name, zfs_offline(pools[0]))
    else:
        r.add('logrule-zfs-offline', '-', None, 'no ZFS host in this build')
    tier14_monitoring(r, api, nodes, journald, bare)


# ── 0.5.8: anomalies, the monitoring view, netconsole and pstore (section 3, phases 3 to 5). Written, not run yet ──
ANOMALIES = """
import json, shutil, sys, tempfile, time
from storageforge_index import hostlogs, loganomaly
from storageforge_index.db import Database
base, flood = sys.stdin.read().split('\\n@@@@\\n')
now = time.time() - time.time() % 300
W = loganomaly.WEEK_SECS
d = tempfile.mkdtemp(); db = Database(d + '/t.db'); conn = db.connect(); db.migrate(conn)
def shifted(text, back, tag):
    p = hostlogs.parse(text, now)
    for x in p['lines']:
        x['at_us'] -= int(back * 1e6); x['key'] = x['key'] + tag
    return p
for k in (3, 2, 1):                      # the same real journal, as it would have been one, two and three weeks ago
    hostlogs.store(conn, 'h', shifted(base, k * W, 'w%d' % k), now - k * W)
hostlogs.store(conn, 'h', hostlogs.parse(base, now), now)
out = {'ordinary': sorted(loganomaly.problems(conn, now)), 'kinds': conn.scalar('SELECT count(*) FROM host_log_kinds'),
       'lines': conn.scalar('SELECT count(*) FROM host_log_lines WHERE collected_at = :t', {'t': int(now)}), 'weeks': loganomaly.assess(conn, 'h', now)['weeks']}
hostlogs.store(conn, 'h', hostlogs.parse(flood, now + 1), now + 1)
out['flooded'] = {k: v[3] for k, v in loganomaly.problems(conn, now + 1).items()}
conn.close(); shutil.rmtree(d, True)
print(json.dumps(out))
"""


def tier14_monitoring(r, api, nodes, journald, bare):
    fetch = 'from storageforge_index import hostlogs; import sys; print(hostlogs.script(int(sys.argv[1])))'

    def anomalies(node):
        def check():
            since = str(int(time.time()) - 7 * 86400)
            base = ssh(node.name, 'sudo -n -u scan sh -s', stdin=in_product(fetch, since))
            token = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(12))       # letters only: a number would be blanked
            sudo(node.name, f'for i in $(seq 1 600); do logger -t {TAG}-flood -p user.notice "flood line $i"; done; logger -t {TAG}-kind -p user.err "sflab never seen {token}"')
            flood = ssh(node.name, 'sudo -n -u scan sh -s', stdin=in_product(fetch, since))
            got = json.loads(in_product(ANOMALIES, stdin=base + '\n@@@@\n' + flood))
            want(got['weeks'] == 3, f'three weeks were laid down and the baseline sees {got["weeks"]}')
            want(got['ordinary'] == [], f'an ordinary hour of {node.name}, against three weeks of the same, raised {got["ordinary"]}')
            want(0 < got['kinds'] < got['lines'], f'{got["lines"]} real lines made {got["kinds"]} kinds: their numbers and names were not blanked')
            flooded = got['flooded']
            want('log-volume:h' in flooded, f'600 lines more than usual raised no volume warning: {flooded}')
            want('log-new-kind:h' in flooded and token in flooded['log-new-kind:h'], f'the line of a new kind was not said: {flooded.get("log-new-kind:h")!r}')
            return f'{got["lines"]} real lines in {got["kinds"]} kinds; an ordinary hour quiet; the flood: {flooded["log-volume:h"][:120]!r}'
        return check

    def monitor_view():
        def check():
            got = {h['host']: h for h in api.get('/api/hostlogs/monitor')['hosts']}
            status = {s['host']: s for s in api.get('/api/hostlogs/status')['hosts']}
            missing = [n.name for n in journald + bare if n.name not in got]
            want(not missing, f'the monitoring view leaves out {missing}')
            for n in journald:
                i, s = got[n.name]['ingest'], status.get(n.name)
                want(s and i['state'] == s['state'] and i['last_line'] == s['newest'] and i['signed'] == s['signed'],
                     f'{n.name}: the view says {i}, the status says {s}')
            for n in bare:
                want(got[n.name]['ingest']['state'] == 'no_journal', f'{n.name} has no journal and the view says {got[n.name]["ingest"]}')
            ranks = [h['rank'] for h in api.get('/api/hostlogs/monitor')['hosts']]
            want(ranks == sorted(ranks), f'hosts with something to look at do not come first: {ranks}')
            return f'{len(got)} hosts, the ingest of each as its status says'
        return check

    controller = next((n for n in nodes if n.can('controller')), None)

    def netconsole_plan(node):
        def check():
            want(controller, 'no controller in this build')
            got = api.get('/api/hostlogs/netconsole')
            want(got['receiver']['listening'], f'the controller does not listen for netconsole: {got["receiver"]}. compose.lab.yml sets STORAGEFORGE_NETCONSOLE_LISTEN')
            api('PUT', f'/api/hostlogs/netconsole/{node.name}', {'address': node.ip, 'port': 6665})
            plan = api.post('/api/changes', {'name': 'sflab netconsole', 'tasks': [{'type': 'netconsole', 'host': node.name, 'params': {'target': controller.ip}}]})
            demo.deploy(api, 'changes', plan['id'], 'netconsole on')
            try:
                conf = sudo(node.name, 'cat /etc/modprobe.d/storageforge-netconsole.conf').strip()
                want(conf.startswith('options netconsole netconsole=+6665@') and f',6666@{controller.ip}/' in conf, f'the file it wrote: {conf!r}')
                want(sudo(node.name, 'test -d /sys/module/netconsole && echo yes || echo no').strip() == 'yes', 'netconsole is not loaded')
                token = secrets.token_hex(6)
                sudo(node.name, f'echo "<2>sflab-netconsole-{token}" > /dev/kmsg')
                found = t.wait_for('the line over netconsole', lambda: [e for e in api.get(f'/api/hostlogs?host={node.name}&q={token}&limit=10')['entries']
                                                                        if e['via'] == 'netconsole'], timeout=60)
                want(found[0]['priority'] == 2 and not found[0]['signed'], f'it came, but as {found[0]}')
                src = next(x for x in api.get('/api/hostlogs/netconsole')['sources'] if x['host'] == node.name)
                want(src['packets'] >= 1 and src['last_at'], f'the source does not count what came: {src}')
            finally:
                undo = api.post('/api/changes', {'name': 'sflab netconsole off', 'tasks': [{'type': 'netconsole', 'host': node.name,
                                                                                            'params': {'target': controller.ip, 'state': 'absent'}}]})
                demo.deploy(api, 'changes', undo['id'], 'netconsole off')
            left = sudo(node.name, 'ls /etc/modprobe.d/storageforge-netconsole.conf /etc/modules-load.d/storageforge-netconsole.conf 2>/dev/null; true').strip()
            want(not left, f'the way back left {left}')
            after = secrets.token_hex(6)
            sudo(node.name, f'echo "<2>sflab-netconsole-{after}" > /dev/kmsg; sleep 8')
            came = [e for e in api.get(f'/api/hostlogs?host={node.name}&q={after}&limit=10')['entries'] if e['via'] == 'netconsole']
            api('DELETE', f'/api/hostlogs/netconsole/{node.name}')
            want(not came, 'a line still came over netconsole after the way back')
            return f'{conf}; a line at crit came over UDP, not signed; the way back removed both files and the next line did not come'
        return check

    def panic(node):
        """The VM is crashed for real, so only when asked (SFLAB_CRASH=1), and only on the throwaway UEFI VM."""
        def check():
            want(controller, 'no controller in this build')
            sudo(node.name, 'modprobe efi_pstore 2>/dev/null; true', check=False)
            backend = sudo(node.name, 'cat /sys/module/pstore/parameters/backend 2>/dev/null; true', check=False).strip()
            want(backend and backend != '(null)', f'{node.name} has no pstore backend ({backend!r}): the crash record would have nowhere to go')
            api('PUT', f'/api/hostlogs/netconsole/{node.name}', {'address': node.ip, 'port': 6665})
            bash = in_product('from storageforge_index import steps_netconsole; print(steps_netconsole.BASH)')
            head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; exit 1; }; info() { :; }; '
                    'act() { :; }; durable() { sync; }\n')
            sudo(node.name, 'bash -s', stdin=head + bash + f'\nt_netconsole {controller.ip} 6666 6665 "" present\n')
            sudo(node.name, 'sysctl -q kernel.panic=10; sync')
            ssh(node.name, 'sudo -n sh -c "sleep 2; echo c > /proc/sysrq-trigger" >/dev/null 2>&1 &', check=False)
            try:
                said = t.wait_for('the panic over netconsole', lambda: [e for e in api.get(f'/api/hostlogs?host={node.name}&q=sysrq&limit=20')['entries']
                                                                        if e['via'] == 'netconsole'], timeout=90)
                t.alerts_now()
                crit = [x for g in api.get(f'/api/notifications?host={node.name}&kind=log-rule')['groups'] for x in g['items'] if x['level'] == 'crit']
                want(crit, f'the panic came over netconsole ({said[0]["message"]!r}) and raised nothing critical')
                demo.wait(f'{node.name} back after the crash', lambda: ssh(node.name, 'echo up', check=False).strip() == 'up', timeout=600)
                scan(api, node)
                t.alerts_now()
                row = api.get(f'/api/hostlogs/monitor?host={node.name}')['hosts'][0]
                ps = row['ingest'].get('pstore')
                want(ps and ps['records'] >= 1, f'after the reboot the scan found no crash record in pstore: {row["ingest"]}')
                note = [x for g in api.get(f'/api/notifications?host={node.name}&kind=log-pstore')['groups'] for x in g['items']]
                want(note and note[0]['level'] == 'warn', f'a crash record and no warning: {note}')
                return (f'the crash over netconsole: {said[0]["message"][:80]!r}; after the reboot {ps["records"]} record(s) in pstore, '
                        + ('read' if ps['read'] else f'not readable: {ps["note"][:80]}'))
            finally:
                sudo(node.name, 'bash -s', stdin=head + bash + f'\nt_netconsole {controller.ip} 6666 6665 "" absent\n', check=False)
                sudo(node.name, 'rm -f /sys/fs/pstore/* 2>/dev/null; rm -rf /var/lib/systemd/pstore/* 2>/dev/null; true', check=False)
                api('DELETE', f'/api/hostlogs/netconsole/{node.name}')
        return check

    if journald:
        r.check('logs-anomalies', journald[0].name, anomalies(journald[0]))
    r.check('logs-monitor-view', '-', monitor_view())
    able = [n for n in journald if n.can('deploy') and not n.can('controller')]
    if able:
        r.check('netconsole-plan', able[0].name, netconsole_plan(able[0]))
    else:
        r.add('netconsole-plan', '-', None, 'no host with systemd that deploys in this build')
    crashable = roles.extra('uefi')
    if crashable and os.environ.get('SFLAB_CRASH') == '1':
        r.check('netconsole-panic-pstore', crashable[0].name, panic(crashable[0]))
    else:
        r.add('netconsole-panic-pstore', crashable[0].name if crashable else '-', None, 'crashes a VM: run with SFLAB_CRASH=1 and the UEFI VM in the build')
