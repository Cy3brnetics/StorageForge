#!/usr/bin/env python3
"""Tier 16 of the KVM lab: a btrfs or ZFS send between two enrolled hosts, each side a signed run, with no root key between them (SF-48).

What the stand-ins in tests/test_sends.py cannot say, and this tier is for: real btrfs receive and zfs receive on real streams, corrupt and
cut off as well as whole, a real forced command under real sudo, and the receiving host's own record, read on that host. tiers.py runs it.

    frm, to   the sender and the receiver. Both are enrolled, and root on one has no way in to the other: the first check says so

A check reads the answer from the VM it is about, never from StorageForge's report of its work. ZFS needs two ZFS hosts: most builds pick one, and show skip.
"""
import json
import re
import secrets
import shlex
import subprocess
import time

import demo
import roles
from demo import ssh

import tiers as t
from tiers_platform import sudo

JOB = '/usr/local/sbin/storageforge-job'
KEYS = '/var/lib/storageforge/deploy/.ssh/authorized_keys'


def run(vm, command, timeout=600):
    """The whole answer of a command on a VM as root, for what is meant to fail."""
    return subprocess.run([demo.LAB, 'ssh', vm, f'sudo -n bash -c {shlex.quote(command)}'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def own_record(vm):
    """What the receiving host itself wrote, read there."""
    text = sudo(vm, 'cat /var/lib/storageforge/receive/*/runs.jsonl 2>/dev/null; true')
    return [json.loads(line) for line in text.splitlines() if line.startswith('{')]


def access_left(frm, to, prefix):
    """Anything of this send still on either host: a key, a conf, a key line."""
    found = sudo(frm.name, f'ls /etc/storageforge/sends/ 2>/dev/null | grep "^{prefix}"; true').split()
    found += sudo(to.name, f'ls /etc/storageforge/receive/ 2>/dev/null | grep "^{prefix}"; true').split()
    found += [x[:60] for x in sudo(to.name, f'grep -- "--serve {prefix}" {KEYS}; true').splitlines()]
    return found


def stolen(frm, to, prefix, line, before=''):
    """What someone who took the job key from the sender can try with it. before: what feeds its stdin."""
    key = sudo(frm.name, f'ls /etc/storageforge/sends/{prefix}*.key').split()[0]
    known = key[:-len('.key')] + '.hostkey'
    return run(frm.name, f'{before}ssh -o BatchMode=yes -o ConnectTimeout=15 -o IdentitiesOnly=yes -i {key} -o HostKeyAlias=storageforge-source '
                         f'-o UserKnownHostsFile={known} -o StrictHostKeyChecking=yes storageforge-deploy@{to.ip} {shlex.quote(line)}')


def runs_of(runs, host, kind):
    return [x for x in runs if x['host'] == host and x['kind'] == kind]


def tier16(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    frm, to = roles.sender(), roles.receiver()

    def no_root_key(a, b):
        got = run(a.name, f'ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new root@{b.ip} true')
        want(got.returncode != 0, f'root on {a.name} can log in to {b.name} as root: this tier would prove nothing')
        return f'root on {a.name} cannot log in to {b.name}: {got.stderr.strip()[-80:]}'
    r.check('send-no-root-key', frm.name, lambda: no_root_key(frm, to))

    # ── refused ─────────────────────────────────────────────────
    outsider = (roles.having('nosystemd') or [None])[0]

    def refused(name):
        made = api.post('/api/tasks', {'name': f'Lab send to {name}', 'host': frm.name, 'blocks': [
            {'type': 'btrfs_send', 'params': {'into': frm.snaps, 'prefix': 'never', 'dst_host': name, 'dst': '/srv/never', 'keep': 0}}]})
        checked = api.post('/api/tasks/check', {'name': 'x', 'host': frm.name, 'blocks': [
            {'type': 'btrfs_send', 'params': {'into': frm.snaps, 'prefix': 'never', 'dst_host': name, 'dst': '/srv/never', 'keep': 0}}]})
        crit = ' '.join(i['text'] for b in checked['blocks'] for i in b['items'] if i['level'] == 'crit')
        want('not enrolled' in crit and 'Set up' in crit and 'setup-script' in crit, f'the check does not say how to enrol it: {crit[:300]}')
        out = api('POST', '/api/deploy/start', {'kind': 'tasks', 'ref': made['id'], 'mode': 'apply', 'run': True}, expect=409)
        want(name in out['hosts'] and 'Set up' in out['error'], f'the refusal does not say why: {out}')
        want(not sudo(frm.name, 'ls /etc/storageforge/sends/ 2>/dev/null; true').split(), 'a key was written for a send that was refused')
        row = t.sql("SELECT outcome, detail_json FROM audit_log WHERE action = 'deploy.start' ORDER BY audit_id DESC LIMIT 1")[0]
        want(row['outcome'] == 'denied' and name in row['detail_json'], f'the audit row: {row}')
        return 'crit with the steps, 409, nothing written, and a denied audit row'
    if outsider:
        r.check('send-refused-not-enrolled', outsider.name, lambda: refused(outsider.name))
    r.check('send-refused-unknown-host', frm.name, lambda: refused('sf-nobody'))

    # ── btrfs: a task, as a timer would run it and by Run now ───
    state = {}
    marker = f'{frm.subvol}/lab-send-marker.bin'

    def report_first():
        made = api.post('/api/tasks', {'name': 'Lab signed btrfs', 'host': frm.name, 'blocks': [
            {'type': 'btrfs_snapshot', 'params': {'subvol': frm.subvol, 'into': frm.snaps, 'prefix': 'signed'}},
            {'type': 'btrfs_send', 'params': {'into': frm.snaps, 'prefix': 'signed', 'dst_host': to.name, 'dst': to.recv, 'keep': 2}}]})
        state.update(task=made['id'], prefix=f'rt{made["id"]}-')
        before = sudo(to.name, f'ls -A {to.recv} 2>/dev/null; cat {KEYS}'), sudo(frm.name, f'ls -A {frm.snaps} 2>/dev/null')
        group = api.post('/api/deploy/start', {'kind': 'tasks', 'ref': made['id'], 'mode': 'report'})['group']
        out = demo.wait('the report', lambda: demo.finished(api, group))
        want(all(x['status'] == 'ok' for x in out['runs']), f'report: {[(x["host"], x["kind"], x["status"]) for x in out["runs"]]}')
        want(runs_of(out['runs'], to.name, 'sends'), 'the receiver had no run of its own')
        after = sudo(to.name, f'ls -A {to.recv} 2>/dev/null; cat {KEYS}'), sudo(frm.name, f'ls -A {frm.snaps} 2>/dev/null')
        want(before == after, 'a report changed something')
        want(not access_left(frm, to, state['prefix']), 'a report left access behind')
        return 'each host reported, and neither changed'
    r.check('send-report-changes-nothing', to.name, report_first)

    def btrfs_full():
        sudo(frm.name, f'head -c 2M /dev/urandom >{marker}')
        runs = demo.deploy(api, 'tasks', state['task'], 'signed btrfs send', run=True)
        kinds = [(x['host'], x['kind']) for x in runs]
        want((to.name, 'sends') in kinds and kinds.index((to.name, 'sends')) < kinds.index((frm.name, 'tasks')), f'the receiver went first: {kinds}')
        names = sudo(to.name, f'ls {to.recv}').split()
        want(len(names) == 1, f'on the receiver: {names}')
        state['first'] = names[0]
        here, there = f'{frm.snaps}/{names[0]}/lab-send-marker.bin', f'{to.recv}/{names[0]}/lab-send-marker.bin'
        want(t.seed_hash(frm.name, here) == t.seed_hash(to.name, there), 'the file reads differently on the receiver')
        source = sudo(frm.name, f'btrfs subvolume show {frm.snaps}/{names[0]}')
        copy = sudo(to.name, f'btrfs subvolume show {to.recv}/{names[0]}')
        own = next(line.split()[-1] for line in source.splitlines() if line.strip().startswith('UUID:'))
        got = re.search(r'Received UUID:\s*(\S+)', copy)
        want(got and got[1] == own, f'received UUID {got and got[1]}, source UUID {own}')
        return f'{names[0]}: same bytes, received UUID is the source UUID'
    r.check('send-btrfs-full', to.name, btrfs_full)

    def run_now_leaves_no_access():
        left = access_left(frm, to, state['prefix'])
        want(not left, f'left behind after a Run now of a task not installed: {left}')
        return 'no key, conf or key line on either host'
    r.check('send-key-goes-after-run-now', to.name, run_now_leaves_no_access)

    def receiver_record():
        got = own_record(to.name)
        want(any(x['verb'] == 'receive' and x['rc'] == 0 and x['name'] == state['first'] and x['sender'] == frm.name for x in got), f'its record: {got[-3:]}')
        rows = api.get(f'/api/deploy/runs?host={to.name}&limit=20')['runs']
        signed = [x for x in rows if x['kind'] == 'sends' and x['status'] == 'ok' and x.get('nonce')]
        want(signed, 'StorageForge has no signed run on the receiver')
        log = sudo(to.name, 'cat /var/log/storageforge/run.log')
        ran = sudo(to.name, 'cat /var/lib/storageforge/run/runs.jsonl')
        for x in signed:
            want(f'run {x["nonce"]}' in log and x['nonce'] in ran, f'the runner on {to.name} has no record of {x["nonce"]}')
        row = t.sql("SELECT detail_json FROM audit_log WHERE action = 'deploy.start' AND outcome = 'ok' ORDER BY audit_id DESC LIMIT 1")[0]
        want(to.name in json.loads(row['detail_json']).get('receivers', []), f'the audit row names no receiver: {row}')
        demo.scan(api, [to.ip])
        seen = t.sql(f"SELECT task, exit_code FROM task_runs WHERE host LIKE '{to.name}%' AND task LIKE 'receive-%'")
        want(any(x['exit_code'] == 0 for x in seen), f'a scan of the receiver found no run of the send: {seen}')
        return f'{len(got)} line(s) of its own, {len(signed)} signed run(s) in its runner log, and a scan brought it home'
    r.check('send-receiver-record', to.name, receiver_record)

    def btrfs_incremental():
        time.sleep(2)
        before = set(sudo(to.name, f'ls {to.recv}').split())
        big = f'{frm.subvol}/lab-send-second.bin'
        sudo(frm.name, f'head -c 8M /dev/urandom >{big}')
        runs = demo.deploy(api, 'tasks', state['task'], 'signed btrfs send again', run=True)
        new = sorted(set(sudo(to.name, f'ls {to.recv}').split()) - before)
        want(new, 'no new snapshot arrived')
        want(t.seed_hash(frm.name, f'{frm.snaps}/{new[-1]}/lab-send-second.bin') == t.seed_hash(to.name, f'{to.recv}/{new[-1]}/lab-send-second.bin'), 'the change reads differently')
        out = ' '.join(x.get('output') or '' for x in runs_of(runs, frm.name, 'tasks'))
        want('changes since' in out and ' -p ' in out, f'not incremental: {out[-400:]}')
        return f'{new[-1]} arrived as changes only'
    r.check('send-btrfs-incremental', to.name, btrfs_incremental)

    def btrfs_retention():
        time.sleep(2)
        demo.deploy(api, 'tasks', state['task'], 'signed btrfs send, third', run=True)
        names = sudo(to.name, f'ls {to.recv}').split()
        want(len(names) == 2, f'keep is 2, and the receiver holds {names}')
        want(state['first'] not in names, f'the oldest is still there: {names}')
        want(any(x['verb'] == 'prune' and x['rc'] == 0 and state['first'] in x['message'] for x in own_record(to.name)), 'its record has no prune')
        return f'{state["first"]} went, on the receiver, by the count in its signed conf'
    r.check('send-btrfs-retention', to.name, btrfs_retention)

    def installed():
        demo.deploy(api, 'tasks', state['task'], 'signed btrfs send, installed')
        want(access_left(frm, to, state['prefix']), 'an installed task has no key: its timer could not send')
        before = set(sudo(to.name, f'ls {to.recv}').split())
        time.sleep(2)
        sudo(frm.name, 'systemctl start sf-task-lab-signed-btrfs.service')
        new = set(sudo(to.name, f'ls {to.recv}').split()) - before
        want(new, f'the timer unit sent nothing: {sudo(frm.name, "journalctl -u sf-task-lab-signed-btrfs -n 20 --no-pager")[-500:]}')
        return f'{sorted(new)[-1]} arrived from the unit, with nobody signing anything'
    r.check('send-from-the-timer-unit', frm.name, installed)

    def only_verbs():
        p = state['prefix']
        got = stolen(frm, to, p, 'recv-probe')
        want(got.returncode == 0 and got.stdout.strip() == 'ok btrfs', f'the key does not even probe: {got.stdout} {got.stderr}')
        tries = ['id', 'cat /etc/shadow', 'recv-list; id', 'recv-list $(id)', 'btrfs receive /', f'recv-state ../../..{to.recv}', 'recv-discard ..', 'rsync --server --daemon .', 'sudo -l']
        for line in tries:
            got = stolen(frm, to, p, line)
            want(got.returncode == 97, f'{line!r} got exit {got.returncode}: {got.stdout[:200]} {got.stderr[:200]}')
            want('uid=' not in got.stdout and 'root:' not in got.stdout, f'{line!r} printed {got.stdout[:200]}')
        return f'{len(tries)} other things refused with 97'
    r.check('send-key-runs-only-verbs', to.name, only_verbs)

    def replayed():
        p = state['prefix']
        nonce = secrets.token_hex(16)
        name = 'signed-replay'
        first = stolen(frm, to, p, f'recv-receive {nonce} {name}', 'head -c 4096 /dev/urandom | ')
        want(first.returncode not in (0, 97), f'garbage was accepted or refused early: {first.returncode} {first.stderr[-300:]}')
        again = stolen(frm, to, p, f'recv-receive {nonce} {name}', 'head -c 4096 /dev/urandom | ')
        want(again.returncode == 97 and 'already used' in again.stderr, f'the same nonce again: {again.returncode} {again.stderr[-300:]}')
        return 'the same nonce twice: refused the second time'
    r.check('send-replayed-nonce', to.name, replayed)

    def corrupt():
        p = state['prefix']
        name = 'signed-corrupt'
        got = stolen(frm, to, p, f'recv-receive {secrets.token_hex(16)} {name}', 'head -c 65536 /dev/urandom | ')
        want(got.returncode != 0, 'garbage was received as a snapshot')
        want(got.stderr.strip(), 'it failed and said nothing')
        want(not sudo(to.name, f'ls -d {to.recv}/{name} 2>/dev/null; true').strip(), 'something of it was left')
        line = own_record(to.name)[-1]
        want(line['verb'] == 'receive' and line['rc'] != 0, f'its record: {line}')
        return f'exit {got.returncode}: {got.stderr.strip()[:120]}'
    r.check('send-btrfs-corrupt-stream', to.name, corrupt)

    def cut_off():
        p = state['prefix']
        name = 'signed-cut'
        snap = f'{frm.snaps}/{name}'
        sudo(frm.name, f'btrfs subvolume snapshot -r {frm.subvol} {snap} >/dev/null; sync')
        got = stolen(frm, to, p, f'recv-receive {secrets.token_hex(16)} {name}', f'btrfs send -q {snap} | head -c 1048576 | ')
        left = sudo(to.name, f'ls -d {to.recv}/{name} 2>/dev/null; true').strip()
        sudo(frm.name, f'btrfs subvolume delete {snap} >/dev/null')
        want(got.returncode != 0, 'a stream cut off at 1 MiB was received as a snapshot')
        want(not left, 'what it left is still there')
        return f'exit {got.returncode}, and nothing left: {got.stderr.strip()[-120:]}'
    r.check('send-btrfs-cut-off-stream', to.name, cut_off)

    def failure_reaches_the_sender():
        """The receiver fails for real, and the sender's own run says so: this folder is read-only for the moment, by a read-only bind."""
        time.sleep(2)
        sudo(to.name, f'mount --bind {to.recv} {to.recv} && mount -o remount,ro,bind {to.recv}')
        try:
            got = run(frm.name, 'systemctl start sf-task-lab-signed-btrfs.service')
            status = sudo(frm.name, 'systemctl is-failed sf-task-lab-signed-btrfs.service; true').strip()
            log = sudo(frm.name, 'journalctl -u sf-task-lab-signed-btrfs -n 30 --no-pager')
        finally:
            sudo(to.name, f'umount {to.recv}')
        want(got.returncode != 0 or status == 'failed', f'the sender reported success: {log[-500:]}')
        want('did not finish' in log, f'the sender does not say the stream failed: {log[-500:]}')
        return 'the unit failed, and its log says why'
    r.check('send-failure-reaches-the-sender', frm.name, failure_reaches_the_sender)

    def scan_user_gets_nothing():
        p = state['prefix']
        sid = sudo(to.name, f'ls /etc/storageforge/receive/ | grep "^{p}"').split()[0].removesuffix('.conf')
        got = run(to.name, f'sudo -n -u scan sudo -n {JOB} --serve {sid} recv-probe')
        want(got.returncode != 0 and 'ok btrfs' not in got.stdout, f'the scan user started a verb: {got.stdout}')
        key = sudo(frm.name, f'ls /etc/storageforge/sends/{p}*.key').split()[0]
        got = run(frm.name, f'sudo -n -u scan cat {key}')
        want(got.returncode != 0, 'the scan user read the job key')
        return 'no sudo for the verbs on the receiver, and the key on the sender is not readable'
    r.check('send-scan-user-gets-nothing', to.name, scan_user_gets_nothing)

    def uninstall():
        demo.deploy(api, 'tasks', state['task'], 'signed btrfs send, uninstall', remove=True)
        left = access_left(frm, to, state['prefix'])
        want(not left, f'left behind: {left}')
        want('storageforge-run' in sudo(to.name, f'cat {KEYS}'), 'the deploy key went too')
        return 'key, conf and key line gone from both hosts, and the copies stay'
    r.check('send-uninstall', to.name, uninstall)

    def plan():
        name = 'lab-plan-send'
        snap = f'{frm.snaps}/{name}'
        made = api.post('/api/changes', {'name': 'Lab signed plan send', 'tasks': [
            {'type': 'snapshot', 'host': frm.name, 'params': {'source': frm.subvol, 'dest': snap, 'readonly': True}},
            {'type': 'btrfs-send', 'host': frm.name, 'params': {'source': snap, 'dest_host': to.name, 'dest': to.recv}}]})
        demo.deploy(api, 'changes', made['id'], 'signed plan send')
        want(t.re_uuid(sudo(to.name, f'btrfs subvolume show {to.recv}/{name}')), 'it did not arrive whole')
        left = access_left(frm, to, f'rc{made["id"]}-')
        want(not left, f'a plan leaves no key behind, and this left {left}')
        runs = demo.deploy(api, 'changes', made['id'], 'signed plan send, again')
        out = ' '.join(x.get('output') or '' for x in runs if x['kind'] == 'changes')
        want('is already there' in out, f'a rerun: {out[-400:]}')
        return 'sent, the key went with the plan, and a rerun changed nothing'
    r.check('send-plan-btrfs', to.name, plan)

    # ── ZFS ─────────────────────────────────────────────────────
    pools = roles.having('zfs')
    zfs_checks = ('send-zfs-full', 'send-zfs-incremental', 'send-zfs-retention', 'send-zfs-corrupt-stream', 'send-zfs-mountpoint', 'send-zfs-no-root-key')
    if len(pools) < 2:
        for check in zfs_checks:
            r.add(check, pools[0].name if pools else '-', None, 'needs two ZFS hosts in this build')
        return
    a, b = pools[:2]
    data, into = f'{a.tag("zfs-pool")}/media', f'{b.tag("zfs-pool")}/signed-{a.name}'
    zstate = {}

    r.check('send-zfs-no-root-key', b.name, lambda: no_root_key(a, b))

    def zfs_task():
        made = api.post('/api/tasks', {'name': 'Lab signed ZFS', 'host': a.name, 'blocks': [
            {'type': 'zfs_snapshot', 'params': {'dataset': data, 'prefix': 'signed'}},
            {'type': 'zfs_send', 'params': {'dataset': data, 'prefix': 'signed', 'dst_host': b.name, 'dst': into, 'keep': 2}}]})
        zstate.update(task=made['id'], prefix=f'rt{made["id"]}-')

    def snapshots(node, dataset):
        return [x.split('@')[1] for x in sudo(node.name, f'zfs list -H -t snapshot -d 1 -s creation -o name {dataset}').split()]

    def guid(node, snap):
        return sudo(node.name, f'zfs get -Hp -o value guid {snap}').strip()

    def zfs_full():
        zfs_task()
        demo.deploy(api, 'tasks', zstate['task'], 'signed zfs send', run=True)
        got = snapshots(b, into)
        want(len(got) == 1 and got[0].startswith('signed-'), f'on the receiver: {got}')
        want(guid(a, f'{data}@{got[0]}') == guid(b, f'{into}@{got[0]}'), 'the guids differ')
        want(sudo(b.name, f'zfs get -H -o value mounted {into}').strip() == 'no', 'it was mounted')
        want(any(x['verb'] == 'receive' and x['rc'] == 0 for x in own_record(b.name)), 'the receiver has no record')
        want(not access_left(a, b, zstate['prefix']), 'a Run now left access behind')
        zstate['first'] = got[0]
        return f'{got[0]}: guids match, not mounted, and the receiver has its own record'
    r.check('send-zfs-full', b.name, zfs_full)

    def zfs_incremental():
        time.sleep(2)
        runs = demo.deploy(api, 'tasks', zstate['task'], 'signed zfs send again', run=True)
        got = snapshots(b, into)
        want(len(got) == 2, f'on the receiver: {got}')
        want(guid(a, f'{data}@{got[-1]}') == guid(b, f'{into}@{got[-1]}'), 'the guids differ')
        out = ' '.join(x.get('output') or '' for x in runs_of(runs, a.name, 'tasks'))
        want('changes since' in out and '-i @' in out, f'not incremental: {out[-400:]}')
        return f'{got[-1]} arrived as changes only'
    r.check('send-zfs-incremental', b.name, zfs_incremental)

    def zfs_retention():
        time.sleep(2)
        demo.deploy(api, 'tasks', zstate['task'], 'signed zfs send, third', run=True)
        got = snapshots(b, into)
        want(len(got) == 2 and zstate['first'] not in got, f'keep is 2, and the receiver holds {got}')
        want(any(x['verb'] == 'prune' and x['rc'] == 0 for x in own_record(b.name)), 'its record has no prune')
        return f'{zstate["first"]} went, by the count in the signed conf'
    r.check('send-zfs-retention', b.name, zfs_retention)

    def zfs_corrupt():
        demo.deploy(api, 'tasks', zstate['task'], 'signed zfs send, installed')
        before = snapshots(b, into)
        got = stolen(a, b, zstate['prefix'], f'recv-receive {secrets.token_hex(16)} signed-corrupt', 'head -c 65536 /dev/urandom | ')
        want(got.returncode != 0, 'garbage was received')
        want(got.stderr.strip(), 'it failed and said nothing')
        want(snapshots(b, into) == before, 'the snapshots changed')
        line = own_record(b.name)[-1]
        want(line['rc'] != 0, f'its record: {line}')
        demo.deploy(api, 'tasks', zstate['task'], 'signed zfs send, uninstall', remove=True)
        return f'exit {got.returncode}: {got.stderr.strip()[:120]}'
    r.check('send-zfs-corrupt-stream', b.name, zfs_corrupt)

    def zfs_mountpoint():
        """With child datasets a stream carries properties. A sender that was taken over could name /etc: the copy must not take it."""
        source, target = f'{a.tag("zfs-pool")}/labmount', f'{b.tag("zfs-pool")}/labmount-copy'
        sudo(a.name, f'zfs create -o mountpoint=/mnt/lab-send-mountpoint {source}')
        made = api.post('/api/tasks', {'name': 'Lab signed ZFS mountpoint', 'host': a.name, 'blocks': [
            {'type': 'zfs_snapshot', 'params': {'dataset': source, 'prefix': 'signed', 'recursive': True}},
            {'type': 'zfs_send', 'params': {'dataset': source, 'prefix': 'signed', 'dst_host': b.name, 'dst': target, 'keep': 0, 'recursive': True}}]})
        demo.deploy(api, 'tasks', made['id'], 'signed zfs send with properties', run=True)
        got = sudo(b.name, f'zfs get -H -o value mountpoint {target}').strip()
        want(got != '/mnt/lab-send-mountpoint', f'the copy took the mountpoint of the stream: {got}')
        want(sudo(b.name, f'zfs get -H -o value mounted {target}').strip() == 'no', 'it was mounted')
        return f'its mountpoint is {got}, from its parent, and not what the stream said'
    r.check('send-zfs-mountpoint', b.name, zfs_mountpoint)
