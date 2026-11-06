#!/usr/bin/env python3
"""Tier 14 of the KVM lab: host logs (hostlogs.py) against real journald on real distros.

NOT RUN. This file was written without a lab: the KVM lab cannot run where it was written, so nothing here has been executed, not
even once against a VM, and it may need fixes on its first run. The unit tests in tests/test_hostlogs.py run the same code against
a stand-in journalctl and stay the proof until this tier passes. Remove this paragraph when it has.

What a stand-in journalctl cannot say, and this tier is for:

    read       a scan user in the systemd-journal group reads the whole journal: the line written on the VM comes back with its level
               and identifier, and /api/hostlogs/counts and /units agree with what the VM's own journalctl lists
    limited    the same user outside the group is told so, and nothing is stored; the access script adds the group, and the next
               scan reads back the line written while it could not
    no journal a host without journald says so (sf-alpine, the one config with no systemd) and stores nothing
    secrets    a line holding password=hunter2, written with logger on the VM, is stored with the secret removed, in the table and not
               only in the API's answer
    caps       the 30-day and per-host row limits, applied by the product's own store() to real journal text read from the VM. That
               runs in a throwaway database inside the sf-ctl container, with the clock moved on 22 and 31 days and the row limit set
               to 50, because the real limits (30 days, 500000 rows) can't be waited for or filled in a lab run

A check reads the answer from the VM it is about, never from StorageForge's report of its work. tiers.py runs it.
"""
import json
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
    return api.get(f'/api/hostlogs?host={name}&q={q}&limit={limit}')['entries']


def stored_rows(name):
    return t.sql(f"SELECT count(*) n FROM host_log_lines WHERE host = '{name}'")[0]['n']


def scan(api, node):
    demo.scan(api, [node.ip])


def tier14(r):
    api = demo.sign_in()
    demo.scan_everything(api)
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

    # ── the 30-day and row limits, on real journal text ─────────
    fetch = 'from storageforge_index import hostlogs; import sys; print(hostlogs.script(int(sys.argv[1])))'
    caps = '''
import json, sys, tempfile, time
from storageforge_index import hostlogs
from storageforge_index.db import Database
text, now = sys.stdin.read(), time.time()
out = {'keep_days': hostlogs.KEEP_DAYS, 'keep_rows': hostlogs.KEEP_ROWS, 'first_days': hostlogs.FIRST_DAYS}
def stored(shift):
    d = tempfile.mkdtemp(); db = Database(d + '/t.db'); conn = db.connect(); db.migrate(conn)
    at = now + shift * 86400
    parsed = hostlogs.parse(text, at)
    hostlogs.store(conn, 'h', parsed, at)
    rows = [r[0] for r in conn.all('SELECT at_us FROM host_log_lines WHERE host = :h', {'h': 'h'})]
    conn.close()
    return parsed, rows
for shift in (0, 22, 31):
    parsed, rows = stored(shift)
    newest = sorted((x['at_us'] for x in parsed['lines']), reverse=True)
    out[str(shift)] = {'read': len(parsed['lines']), 'kept': len(rows), 'state': parsed['state'],
                       'newest_kept': bool(rows) and min(rows) >= newest[max(0, len(rows) - 1)]}
print(json.dumps(out))
'''

    def limits(node):
        def check():
            sudo(node.name, f'for i in $(seq 1 150); do logger -t {TAG}-fill -p user.notice "fill line $i"; done')
            since = int(time.time()) - 7 * 86400
            text = ssh(node.name, 'sudo -n -u scan sh -s', stdin=in_product(fetch, str(since)))
            want('@@who' in text and '@@end' in text, f'the collection script did not run to its end on {node.name}: {text[-300:]}')
            row_cap = json.loads(in_product(caps, stdin=text, env=['STORAGEFORGE_LOG_KEEP_ROWS=50', 'STORAGEFORGE_LOG_KEEP_DAYS=30']))
            want(row_cap['keep_rows'] == 50, f'the row limit did not take: {row_cap}')
            now = row_cap['0']
            want(now['state'] == 'ok' and now['read'] > 50, f'the VM gave {now["read"]} lines: not enough to reach the limit')
            want(0 < now['kept'] <= 50 and now['newest_kept'], f'kept {now["kept"]} of {now["read"]} with the limit at 50, newest first: {now}')
            day_cap = json.loads(in_product(caps, stdin=text, env=['STORAGEFORGE_LOG_KEEP_ROWS=500000', 'STORAGEFORGE_LOG_KEEP_DAYS=30']))
            want(day_cap['keep_days'] == 30 and day_cap['first_days'] == 7, f'the limits: {day_cap}')
            young, old = day_cap['22'], day_cap['31']
            want(young['kept'] == young['read'] > 0, f'lines at most 29 days old were dropped: {young}')
            want(old['kept'] == 0 and old['read'] > 0, f'lines more than 30 days old were kept: {old}')
            return f'{now["read"]} real lines: 50 newest kept at a limit of 50, all kept at 29 days, none at 31'
        return check
    for node in journald:
        r.check('hostlogs-caps', node.name, limits(node))
