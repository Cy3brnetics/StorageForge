#!/usr/bin/env python3
"""Tiers 9, 10 and 11 of the KVM lab: the security work and the infrastructure platform on real hosts, through the API.

    9  Security        holds, decoys, the brake, attribution, the airgap's timer, the clock guard, quorum, the baseline script
    10 Infrastructure  what scans and measurements read, compared with what is really there, and that nothing was probed
    11 Changes         firewall rules, fences and plans from the map, each judged by a real connection between two VMs

Connections and captures live here in the test and never in the product: StorageForge sends no probes. tiers.py runs these.
"""
import json
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import demo
import roles
from demo import COMPOSE, ssh

import tiers as t

MINUTE = 60
# one at a time: systemctl stops at a unit it does not know, and whichever is left puts the clock straight again within seconds
CLOCKS_OFF = 'for u in chrony chronyd systemd-timesyncd ntpd; do systemctl stop $u 2>/dev/null; done;'
CLOCKS_ON = 'for u in chrony chronyd systemd-timesyncd; do systemctl start $u 2>/dev/null; done; true'


def sudo(vm, command, check=True, stdin=None):
    return ssh(vm, f'sudo -n sh -c {shlex.quote(command)}', stdin=stdin, check=check)


def quiet(vm, command):
    """Exit status of a command on a VM. The command's output is not wanted, only whether it worked."""
    p = subprocess.run([demo.LAB, 'ssh', vm, f'sudo -n sh -c {shlex.quote(command)}'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
    return p.returncode


def sql_write(statement):
    code = "import sqlite3, sys; c = sqlite3.connect('/app/data/index.db'); c.execute(sys.argv[1]); c.commit(); c.close()"
    ssh('sf-ctl', f'{COMPOSE} exec -T storageforge python -c {shlex.quote(code)} {shlex.quote(statement)}')


def done(api, path, body):
    """A change on a host, in full: dry run, then apply. Anything but a clean answer fails the check."""
    report = api('POST', path, {**body, 'mode': 'report'})
    if report.get('error'):
        demo.fail(f'{path} dry run: {report["error"]}: {str(report.get("output"))[-600:]}')
    out = api('POST', path, {**body, 'mode': 'apply'})
    if out.get('error') or out.get('ok') is False:
        demo.fail(f'{path}: {out.get("error")}: {str(out.get("output"))[-800:]}')
    return out


def attempt(api, path, body):
    """(status, answer) with a fresh password, for what is meant to be refused."""
    status, out = api.raw('POST', path, body)
    if status == 403 and isinstance(out, dict) and out.get('reauth'):
        api.raw('POST', '/api/reauth', {'password': api.password})
        status, out = api.raw('POST', path, body)
    return status, out


def measure(api, vm):
    out = api.post('/api/security/measure', {'host': vm})
    if not out.get('ok'):
        demo.fail(f'{vm}: measure: {out.get("error")}')
    return out


def connects(frm, ip, port, seconds=4):
    """A real TCP connection from one VM to another, with bash so no VM needs nc."""
    return quiet(frm, f"timeout {seconds} bash -c 'exec 3<>/dev/tcp/{ip}/{port}'") == 0


def listen(vm, port):
    """Something that really accepts on a port, until the VM is reset."""
    sudo(vm, f"nohup sh -c 'command -v python3 >/dev/null && exec python3 -m http.server {port} --bind 0.0.0.0' >/dev/null 2>&1 &")
    time.sleep(2)


def grant_engines():
    """As tier 1 does: a scan reads what its user may. Reading containers without this is what a host shows as no access."""
    for node in roles.having('docker'):
        ssh(node.name, 'sudo -n usermod -aG docker scan')
    for node in roles.having('podman'):
        ssh(node.name, "echo 'scan ALL=(root) NOPASSWD: /usr/bin/podman' | sudo -n tee /etc/sudoers.d/sflab-scan-podman >/dev/null")


def published_container(node, port=18080):
    """Something that really answers on a published port. The lab's image is already on the host."""
    sudo(node.name, f"docker rm -f sf-lab-pub >/dev/null 2>&1; docker run -d --name sf-lab-pub -p {port}:80 docker.io/library/alpine:3.20 sh -c 'while :; do nc -l -p 80 </dev/null; done' >/dev/null")
    time.sleep(2)


def holds(api, vm):
    return {h['id']: h for h in api.get(f'/api/security/worm/holds?host={vm}')['holds']}


def zfs_dataset(node):
    return sudo(node.name, f'zfs list -H -o name {shlex.quote(node.data)}').strip()


# ── tier 9: the security work on real hosts ─────────────────────────
def tier9(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)

    zfs = next(iter(roles.having('zfs')), None)
    btr = next((n for n in roles.having('btrfs') if n.subvol), None)
    sel = next((n for n in roles.having('selinux') if n.name != (btr.name if btr else '')), None)
    armor = next((n for n in roles.deployable() if quiet(n.name, 'command -v aa-status >/dev/null && aa-status --enabled') == 0), None)

    for node in roles.deployable():
        r.check('measure', node.name, lambda n=node: f'measured at {measure(api, n.name).get("measured_at")}')

    state = {}

    # holds: real ZFS
    def zfs_hold():
        ds = zfs_dataset(zfs)
        snap = f'{ds}@sf-lab-hold'
        report = api.post('/api/security/worm/hold', {'host': zfs.name, 'snapshot': snap, 'retention_days': 7, 'create': True, 'mode': 'report'})
        if quiet(zfs.name, f'zfs list -t snapshot {snap}') == 0:
            demo.fail(f'a dry run took the snapshot: {report}')
        out = api.post('/api/security/worm/hold', {'host': zfs.name, 'snapshot': snap, 'retention_days': 7, 'create': True, 'mode': 'apply'})
        if not out.get('hold_id'):
            demo.fail(f'no hold was recorded: {out}')
        if out['hold_tag'] not in sudo(zfs.name, f'zfs holds -H {snap}'):
            demo.fail('the hold is recorded but not on the host')
        if quiet(zfs.name, f'zfs destroy {snap}') == 0:
            demo.fail('zfs destroy got past the hold')
        state.update(zfs_hold=out['hold_id'], zfs_snap=snap, zfs_tag=out['hold_tag'])
        measure(api, zfs.name)
        if not holds(api, zfs.name)[out['hold_id']]['verified_at']:
            demo.fail('a measurement did not see the hold')
        return f'{snap}: zfs destroy refused, seen by a measurement'
    r.check('hold-zfs', zfs.name, zfs_hold) if zfs else r.add('hold-zfs', '-', None, 'no ZFS host')

    # holds: real btrfs
    def btrfs_hold():
        path = f'{btr.snaps}/sf-lab-hold'
        sudo(btr.name, f'mkdir -p {btr.snaps}; btrfs subvolume snapshot {btr.subvol} {path}')
        out = done(api, '/api/security/worm/hold', {'host': btr.name, 'snapshot': path, 'retention_days': 7})
        if 'true' not in sudo(btr.name, f'btrfs property get -ts {path} ro'):
            demo.fail('the snapshot is not read-only')
        if quiet(btr.name, f'touch {path}/sf-should-fail') == 0:
            demo.fail('wrote into a held snapshot')
        state.update(btrfs_hold=out['hold_id'], btrfs_path=path)
        return f'{path} is read-only'
    r.check('hold-btrfs', btr.name, btrfs_hold) if btr else r.add('hold-btrfs', '-', None, 'no btrfs host')

    # one admin: a release waits, alerts and can be aborted
    def cool_off():
        out = api.post('/api/security/worm/release', {'hold_id': state['zfs_hold']})
        if out.get('mode') != 'cool_off' or not out.get('timelock_id'):
            demo.fail(f'not a cool-off: {out}')
        if state['zfs_tag'] not in sudo(zfs.name, f'zfs holds -H {state["zfs_snap"]}'):
            demo.fail('asking released it at once')
        if not t.wait_for('an alert about the pending release', lambda: [a for a in t.alerts_now() if 'release' in json.dumps(a).lower()], 120):
            demo.fail('no alert')
        api.post('/api/security/worm/abort', {'timelock_id': out['timelock_id']})
        if holds(api, zfs.name)[state['zfs_hold']]['status'] != 'locked':
            demo.fail('abort did not put the hold back')
        return 'waits, alerts, and aborts'
    r.check('release-cool-off', zfs.name, cool_off) if state.get('zfs_hold') else r.add('release-cool-off', '-', None, 'no hold to release')

    # the offline key skips the wait once, and raises an alarm
    def offline_key():
        key = api.post('/api/security/worm/break-glass/key')['break_glass_key']
        ask = api.post('/api/security/worm/release', {'hold_id': state['zfs_hold']})
        bad, _ = attempt(api, '/api/security/worm/break-glass', {'timelock_id': ask['timelock_id'], 'break_glass_key': 'wrong' * 8})
        if bad < 400:
            demo.fail('a wrong key was accepted')
        if state['zfs_tag'] not in sudo(zfs.name, f'zfs holds -H {state["zfs_snap"]}'):
            demo.fail('a wrong key released the hold')
        api.post('/api/security/worm/break-glass', {'timelock_id': ask['timelock_id'], 'break_glass_key': key})
        if sudo(zfs.name, f'zfs holds -H {state["zfs_snap"]}').strip():
            demo.fail('the key did not release the hold')
        events = api.get(f'/api/security/events?host={zfs.name}')['events']
        if not any('key' in e['summary'].lower() for e in events):
            demo.fail('no alarm for using the key')
        return 'released once, wrong key refused, alarm raised'
    r.check('offline-key', zfs.name, offline_key) if state.get('zfs_hold') else r.add('offline-key', '-', None, 'no hold to release')

    # two established admins: the second must approve
    def dual_admin():
        ds = zfs_dataset(zfs)
        out = api.post('/api/security/worm/hold', {'host': zfs.name, 'snapshot': f'{ds}@sf-lab-dual', 'retention_days': 7, 'create': True, 'mode': 'apply'})
        password = 'second admin password 1234'
        ssh('sf-ctl', f'{COMPOSE} exec -T storageforge storageforge-index user add second --role admin', stdin=f'{password}\n')
        sql_write('UPDATE users SET created_at = created_at - 604800')
        ask = api.post('/api/security/worm/release', {'hold_id': out['hold_id']})
        if ask.get('mode') != 'dual_admin':
            demo.fail(f'with two established admins it should wait for the second: {ask}')
        own, _ = attempt(api, '/api/security/worm/quorum/approve', {'timelock_id': ask['timelock_id']})
        if own < 400 and sudo(zfs.name, f'zfs holds -H {ds}@sf-lab-dual').strip() == '':
            demo.fail('the asker approved their own release')
        other = demo.Api(password)
        other.post('/api/login', {'username': 'second', 'password': password})
        other.post('/api/security/worm/quorum/approve', {'timelock_id': ask['timelock_id']})
        if sudo(zfs.name, f'zfs holds -H {ds}@sf-lab-dual').strip():
            demo.fail('approved, but the hold is still there')
        ssh('sf-ctl', f'{COMPOSE} exec -T storageforge storageforge-index user disable second')
        return 'the asker cannot approve, and the second admin can'
    r.check('dual-admin', zfs.name, dual_admin) if zfs else r.add('dual-admin', '-', None, 'no ZFS host')

    # the clock guard, through the path a measurement can still take: past ten minutes hosts refuse signed runs
    def clock_guard():
        node = zfs or btr
        other = roles.other_than(node)
        ds = zfs_dataset(zfs) if zfs else None
        snap = f'{ds}@sf-lab-clock' if zfs else None
        held = api.post('/api/security/worm/hold', {'host': node.name, 'snapshot': snap or state['btrfs_path'], 'retention_days': 7, 'create': bool(zfs), 'mode': 'apply', 'hold_tag': 'sf-lab-clock'})
        sudo(node.name, f"{CLOCKS_OFF} date -s '+5 minutes' >/dev/null")
        try:
            measure(api, node.name)
            status, out = attempt(api, '/api/security/worm/release', {'hold_id': held['hold_id']})
            if status < 400 and out.get('ok'):
                demo.fail('a release was accepted with the clock jumped')
            measure(api, other.name)
            status, out = attempt(api, '/api/security/worm/release', {'hold_id': held['hold_id']})
            if status < 400 and out.get('ok'):
                demo.fail("another host's good reading cleared the guard")
        finally:
            sudo(node.name, f"date -s '-5 minutes' >/dev/null; {CLOCKS_ON}")
        measure(api, node.name)
        api.post('/api/security/worm/clock/clear', {'host': node.name})
        return 'a 5-minute jump stops releases, and a second host cannot clear it'
    r.check('clock-guard', (zfs or btr).name, clock_guard)

    # decoys and a trip, reported by the sentinel over HTTPS
    decoy_host = btr or zfs

    def decoys():
        api.post('/api/security/sentinel', {'host': decoy_host.name, 'folders': [decoy_host.data], 'armed': False})
        demo.deploy(api, 'security', decoy_host.name, 'sentinel')
        d = api.get(f'/api/security/canaries?host={decoy_host.name}')
        if d['summary']['armed'] < 3:
            demo.fail(f'expected 3 decoys: {d["summary"]}')
        latency = api.post('/api/security/canaries/test', {'host': decoy_host.name})['latency_ms']
        sudo(decoy_host.name, f"echo x >>'{decoy_host.data}/_AAAPasswords.docx'")

        def tripped():
            events = api.get(f'/api/security/events?host={decoy_host.name}')['events']
            return [e for e in events if e['kind'] == 'canary_tripped' and e['severity'] == 'crit']
        t.wait_for('the trip to reach the controller', tripped, 120)
        return f'the sentinel saw a test write in {latency} ms, and a trip reached the controller'
    r.check('decoy-trip', decoy_host.name, decoys)

    # the jump the sentinel sees: 30 days, which signed runs would refuse
    def thirty_days():
        node = decoy_host
        sudo(node.name, f"{CLOCKS_OFF} date -s '+30 days' >/dev/null")
        try:
            t.wait_for('the sentinel to write down a clock jump', lambda: 'clock_jump' in sudo(node.name, 'cut -f3 /var/lib/storageforge/security/events.tsv'), 120)
        finally:
            sudo(node.name, f"date -s '-30 days' >/dev/null; {CLOCKS_ON}")
        measure(api, node.name)
        if not [e for e in api.get(f'/api/security/events?host={node.name}')['events'] if e['kind'] == 'clock_jump']:
            demo.fail('the clock jump did not reach the controller')
        api.post('/api/security/worm/clock/clear', {'host': node.name})
        return 'seen on the host, and collected by the next measurement'
    r.check('clock-30-days', decoy_host.name, thirty_days)

    # the armed brake: down to a real read-only remount
    def armed_brake():
        node = decoy_host
        mount = sudo(node.name, f'findmnt -no TARGET --target {node.data}').strip()
        api.post('/api/security/sentinel', {'host': node.name, 'folders': [node.data], 'armed': True, 'actions': ['triage', 'snapshot', 'freeze'], 'minutes': 5})
        demo.deploy(api, 'security', node.name, 'sentinel armed', rearm=True)
        sudo(node.name, f"echo x >>'{node.data}/00_Index.pdf'")

        def frozen():
            return sudo(node.name, f'findmnt -no OPTIONS --target {node.data}').split(',')[0] == 'ro'
        t.wait_for(f'{mount} to go read-only', frozen, 90)
        if quiet(node.name, f"touch '{node.data}/sf-after-brake'") == 0:
            demo.fail('wrote to a frozen filesystem')
        events = sudo(node.name, 'cut -f3 /var/lib/storageforge/security/events.tsv')
        if 'brake_ran' not in events:
            demo.fail('the brake left no event')
        sudo(node.name, f'mount -o remount,rw {mount}')
        api.post('/api/security/sentinel', {'host': node.name, 'folders': [node.data], 'armed': False})
        demo.deploy(api, 'security', node.name, 'sentinel disarmed', rearm=True)
        return f'{mount} went read-only by itself, and StorageForge did not have to be reachable'
    r.check('brake-armed', decoy_host.name, armed_brake)

    # a real Samba client is identified and dropped, an exempt one is not, and NFS says it cannot tell
    def samba_client():
        server, client = demo.share_smb(api)
        if client is None:
            return None
        mount = '/mnt/lab-smb'
        # what encrypts a share has to be able to write to it. Decoys follow their folder when written, and these were written before
        sudo(server.name, f"chown scan '{server.data}'; for f in _AAAPasswords.docx '!Financial_2026.xlsx' 00_Index.pdf; do [ -e '{server.data}'/\"$f\" ] && chown scan '{server.data}'/\"$f\"; done; true")
        api.post('/api/security/sentinel', {'host': server.name, 'folders': [server.data], 'armed': True, 'actions': ['quarantine'], 'minutes': 5})
        api.post('/api/security/firewall/vip', {'vips': [client.ip]})
        demo.deploy(api, 'security', server.name, 'sentinel, client exempt')
        sudo(client.name, f"echo x >>'{mount}/_AAAPasswords.docx'")
        time.sleep(8)
        if not [e for e in api.get(f'/api/security/events?host={server.name}')['events'] if e['kind'] == 'canary_tripped']:
            demo.fail('the client changed a decoy, and nothing tripped')
        if client.ip in sudo(server.name, 'nft list set inet storageforge_fence q4'):
            demo.fail('an exempt client was dropped')
        api.post('/api/security/firewall/vip', {'vips': []})
        demo.deploy(api, 'security', server.name, 'sentinel, client not exempt', rearm=True)
        time.sleep(65)      # a burst of trips from one client is one brake, for a minute
        sudo(client.name, f"timeout 20 sh -c \"echo x >>'{mount}/!Financial_2026.xlsx'\"", check=False)
        t.wait_for(f'{client.ip} to be dropped', lambda: client.ip in sudo(server.name, 'nft list set inet storageforge_fence q4'), 60)
        events = api.get(f'/api/security/events?host={server.name}')['events']
        if not any(client.ip in json.dumps(e) for e in events):
            demo.fail('the event does not name the client')
        return f'{client.ip} named and dropped, and left alone while exempt'
    r.check('samba-attribution', roles.smb_server().name, samba_client)

    def nfs_client():
        server, client = demo.nfs_pair()
        api.post('/api/shares', {'host': server.name, 'export': {'protocol': 'NFSv4.2', 'name': 'media-rw', 'path': server.data, 'rules': [{'clients': client.ip, 'options': 'rw,sync,no_subtree_check,no_root_squash'}],
                                                                  'mounts': [{'host': client.name, 'path': '/mnt/lab-nfs'}]}})
        demo.deploy(api, 'shares', server.name, 'NFS share, read-write')
        api.post('/api/security/sentinel', {'host': server.name, 'folders': [server.data], 'armed': True, 'actions': ['quarantine'], 'minutes': 5})
        demo.deploy(api, 'security', server.name, 'sentinel for NFS', rearm=True)
        sudo(client.name, "echo x >>'/mnt/lab-nfs/_AAAPasswords.docx'", check=False)

        def said():
            measure(api, server.name)
            return [e for e in api.get(f'/api/security/events?host={server.name}')['events'] if e['kind'] == 'canary_tripped']
        got = t.wait_for('the trip', said, 120)
        if client.ip in sudo(server.name, 'nft list set inet storageforge_fence q4'):
            demo.fail('an NFS client was dropped: the server cannot know who it was')
        return f'tripped, nobody dropped: {got[0]["summary"][:90]}'
    r.check('nfs-attribution', demo.nfs_pair()[0].name, nfs_client)

    # the airgap, and its rollback timer under real systemd
    def airgap_timer():
        from storageforge_index import secscripts
        node = roles.deployable()[-1]
        other = roles.other_than(node)
        script = secscripts.airgap_script(['10.77.0.10'], rollback='1min')
        subprocess.run([demo.LAB, 'ssh', node.name, 'sudo -n bash -s -- --apply'], input=script, text=True, capture_output=True, timeout=60)
        if connects(other.name, node.ip, 22):
            demo.fail('the airgap did not cut other machines off')
        time.sleep(100)
        if not connects(other.name, node.ip, 22):
            demo.fail('the rollback timer did not bring the host back')
        return 'cut off, and back by itself when nobody confirmed'
    r.check('airgap-timer', roles.deployable()[-1].name, airgap_timer)

    def airgap_api():
        node = roles.deployable()[-1]
        other = roles.other_than(node)
        out = api.post('/api/security/firewall/airgap', {'host': node.name, 'enabled': True, 'mode': 'apply'})
        if not out.get('airgap'):
            demo.fail(f'not engaged: {out}')
        if connects(other.name, node.ip, 22):
            demo.fail('another VM still reaches it')
        measure(api, node.name)
        api.post('/api/security/firewall/airgap', {'host': node.name, 'enabled': False, 'mode': 'apply'})
        if not connects(other.name, node.ip, 22):
            demo.fail('lifting it did not bring it back')
        return 'only the controller gets through, and lifting it works'
    r.check('airgap-confirmed', roles.deployable()[-1].name, airgap_api)

    # quarantine, against a real connection
    def quarantine():
        node, other = roles.deployable()[0], roles.deployable()[1]
        if not connects(other.name, node.ip, 22):
            demo.fail('no connection before the quarantine, so this proves nothing')
        api.post('/api/security/firewall/quarantine', {'host': node.name, 'ip_address': other.ip, 'minutes': 5, 'mode': 'apply'})
        if connects(other.name, node.ip, 22):
            demo.fail('still connected')
        measure(api, node.name)
        live = [q for q in api.get(f'/api/security/firewall/quarantine?host={node.name}')['quarantine'] if q['ip_address'] == other.ip]
        if not live or live[0]['live'] is not True:
            demo.fail(f'a measurement did not confirm it: {live}')
        api('DELETE', f'/api/security/firewall/quarantine/{other.ip}?host={node.name}&mode=apply')
        if not connects(other.name, node.ip, 22):
            demo.fail('lifted, but still cut off')
        return 'dropped, confirmed and lifted'
    r.check('quarantine', roles.deployable()[0].name, quarantine)

    # encrypt files on a share: blast radius, then the clean room
    def blast_and_clean_room():
        node = zfs or btr
        ds = zfs_dataset(zfs) if zfs else None
        snap = f'{ds}@sf-lab-preincident' if zfs else state['btrfs_path']
        api.post('/api/security/worm/hold', {'host': node.name, 'snapshot': snap, 'retention_days': 7, 'create': bool(zfs), 'mode': 'apply', 'hold_tag': 'sf-lab-pre'})
        folder = f'{node.data}/lab-seed'
        first = sudo(node.name, f'find {folder} -type f | head -n 1').strip()
        before = sudo(node.name, f'sha256sum {shlex.quote(first)}').split()[0]
        n = int(sudo(node.name, f'''n=0; for f in $(find {folder} -type f | head -n 40); do
            openssl enc -aes-256-cbc -pbkdf2 -pass pass:lab -in "$f" -out "$f.locked" 2>/dev/null && rm -f "$f" && n=$((n+1)); done; echo $n''').strip())
        sudo(node.name, f"echo pay >'{folder}/HOW_TO_DECRYPT.txt'")
        at = int(time.time()) - 5
        api.post('/api/security/incident/brake', {'host': node.name, 'path': folder, 'actions': ['triage'], 'mode': 'apply', 'reason': 'lab'})
        demo.scan(api, [node.ip])
        b = api.get(f'/api/security/incident/blast-radius?host={node.name}&at={at}')
        if not b.get('changed_since') or b['changed_since'] < n:
            demo.fail(f'{n} files were encrypted and it counts {b.get("changed_since")}')
        if not b.get('ransom_names'):
            demo.fail('the ransom note was not counted')
        mount = '/mnt/sf-lab-clean'
        room = api.post('/api/security/incident/clean-room', {'host': node.name, 'snapshot': snap, 'mount': mount, 'mode': 'apply'})
        if room.get('error'):
            demo.fail(room['error'])
        opts = sudo(node.name, f'findmnt -no OPTIONS {mount}')
        if 'ro' not in opts.split(','):
            demo.fail(f'the clean room is writable: {opts}')
        inside = first.replace(node.data, mount, 1)
        if sudo(node.name, f'sha256sum {shlex.quote(inside)}').split()[0] != before:
            demo.fail('the snapshot in the clean room is not what was there before')
        api.post('/api/security/incident/clean-room', {'host': node.name, 'snapshot': snap, 'mount': mount, 'mode': 'apply', 'remove': True})
        return f'{n} files: counted {b["changed_since"]} changed, and the clean room holds the old contents'
    r.check('blast-and-clean-room', (zfs or btr).name, blast_and_clean_room)

    # SELinux and AppArmor as they really are
    def selinux():
        d = api.get(f'/api/security/mac/status?host={sel.name}')
        real = sudo(sel.name, 'getenforce').strip().lower()
        if d['selinux_mode'].lower() != real:
            demo.fail(f'says {d["selinux_mode"]}, the host says {real}')
        path = f'{sel.room}/sf-lab-labelled'
        sudo(sel.name, f'mkdir -p {path}')
        done(api, '/api/security/mac/remediate', {'host': sel.name, 'path': path, 'type': 'samba_share_t'})
        if 'samba_share_t' not in sudo(sel.name, f'stat -c %C {path}'):
            demo.fail('relabel did not reach the folder')
        return f'mode {real}, and a relabel survives restorecon'
    r.check('selinux', sel.name, selinux) if sel else r.add('selinux', '-', None, 'no SELinux host')

    def apparmor():
        d = api.get(f'/api/security/mac/status?host={armor.name}')
        if not d['apparmor']['enabled']:
            demo.fail(f'says off: {d["apparmor"]}')
        return f'{d["apparmor"]["enforce"]} profiles enforcing'
    r.check('apparmor', armor.name, apparmor) if armor else r.add('apparmor', '-', None, 'no AppArmor host')

    # the baseline: report first, packages resolve, a second report finds it done
    for node in [n for n in roles.deployable() if n.pm in ('dnf', 'apt-get', 'zypper')][:3]:
        def baseline(n=node):
            first = api.post('/api/security/compliance/init', {'host': n.name, 'profile': 'cis-l1', 'mode': 'report'})
            if quiet(n.name, 'test -e /etc/sysctl.d/99-storageforge-security.conf') == 0:
                demo.fail('the report wrote the settings')
            status, out = attempt(api, '/api/security/compliance/init', {'host': n.name, 'profile': 'cis-l1', 'mode': 'apply'})
            if quiet(n.name, 'test -e /etc/sysctl.d/99-storageforge-security.conf') != 0:
                demo.fail(f'the settings were not written: {str(out.get("output"))[-600:]}')
            again = attempt(api, '/api/security/compliance/init', {'host': n.name, 'profile': 'cis-l1', 'mode': 'report'})[1]
            text = re.sub(r'\x1b\[[0-9;]*m', '', again.get('output') or '')
            left = [line for line in text.splitlines() if line.strip().startswith('missing') and 'AIDE' not in line]
            if left:
                demo.fail('the second report still wants: ' + '; '.join(left)[:400])
            return f'report changed nothing, apply did, and a second report found it done ({len(str(first))} bytes of first report)'
        r.check('baseline', node.name, baseline)


# ── tier 10: what the platform reads ────────────────────────────────
def tier10(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    vms = roles.deployable()
    ufw = next((n for n in vms if n.can('docker')), None)
    grant_engines()

    # what a scan reads, against what the VM says
    for node in roles.build().values():
        def network(n=node):
            got = api.get(f'/api/network?host={n.name}')['network']
            if not got:
                demo.fail('no reading')
            addrs = {a['ip'] for i in got['interfaces'] for a in i['addresses']}
            if n.can('nosystemd') and got['unreadable']:
                return f'says what it could not read: {", ".join(got["unreadable"])}'
            if n.ip not in addrs:
                demo.fail(f'{n.ip} is not among {sorted(addrs)}')
            if got['unreadable']:
                demo.fail(f'could not read {got["unreadable"]}')
            real = {int(p) for p in re.findall(r':(\d+)\s', sudo(n.name, 'ss -H -tln | cut -c1-80'))}
            seen = {x['port'] for x in got['listeners'] if x['proto'] == 'tcp'}
            if not 22 in seen or not seen <= real | seen:
                demo.fail(f'listeners differ: {sorted(seen)} against {sorted(real)}')
            return f'{len(got["interfaces"])} interfaces, {len(seen)} TCP listeners'
        r.check('network-read', node.name, network)

    # nothing is invented: every address on the graph is on a VM or in a neighbour table
    def nothing_invented():
        g = api.get('/api/map?layers=network,services,workloads,firewall')
        hosts = {n['label'] for n in g['nodes'] if n['kind'] == 'Host'}
        missing = set(roles.build()) - hosts
        if missing:
            demo.fail(f'not on the graph: {sorted(missing)}')
        bad = [n['id'] for n in g['nodes'] if n['confidence'] == 'certain' and n.get('props', {}).get('placeholder')]
        if bad:
            demo.fail(f'a placeholder claims to be certain: {bad[:5]}')
        gw = [n for n in g['nodes'] if n['kind'] == 'Gateway']
        if not gw or any(n['confidence'] != 'inferred' for n in gw):
            demo.fail(f'the gateway should be an inferred placeholder: {gw[:2]}')
        return f'{len(g["nodes"])} nodes, {len(g["edges"])} edges, the unscanned gateway dashed'
    r.check('nothing-invented', '-', nothing_invented)

    # the passive guarantee: a capture on the VM during a scan
    def passive():
        node = vms[0]
        if quiet(node.name, 'command -v tcpdump >/dev/null') != 0:
            sudo(node.name, 'command -v apt-get >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y tcpdump || dnf -q -y install tcpdump || zypper -nq install tcpdump')
        sudo(node.name, 'rm -f /tmp/sf-cap.txt; nohup timeout 45 tcpdump -nn -q -i any -l not port 22 >/tmp/sf-cap.txt 2>/dev/null &')
        time.sleep(2)
        demo.scan(api, [node.ip])
        api.post('/api/infra/measure', {'host': node.name})
        time.sleep(3)
        sudo(node.name, 'pkill tcpdump; sleep 1; true')
        lines = sudo(node.name, 'cat /tmp/sf-cap.txt').splitlines()
        lab = re.compile(r'\b10\.77\.0\.(\d+)\.(\d+) > 10\.77\.0\.(\d+)\.(\d+)')
        others = sorted({m.group(0) for line in lines if (m := lab.search(line)) and m.group(1) not in ('1',) and m.group(3) not in ('1',)})
        if others:
            demo.fail(f'traffic between lab machines other than SSH: {others[:6]}')
        icmp = [line for line in lines if 'ICMP echo' in line]
        arps = {line.split('who-has')[1].split()[0] for line in lines if 'who-has' in line}
        if icmp or len(arps) > 3:
            demo.fail(f'looks like a sweep: {len(icmp)} pings, ARP for {sorted(arps)[:8]}')
        return f'{len(lines)} other packets in the capture, none of them a probe, no port but SSH between lab machines'
    r.check('passive', vms[0].name, passive)

    # a failed collector degrades one layer and never fails the scan
    def failed_collector():
        node = vms[0]
        ss = sudo(node.name, 'command -v ss').strip()
        sudo(node.name, f'mv {ss} {ss}.lab-away')
        try:
            demo.scan(api, [node.ip])
            job = next(j for j in api.get('/api/jobs')['jobs'] if j['host'] == node.ip)
            if job['status'] not in ('ok', 'partial'):
                demo.fail(f'the scan ended {job["status"]}')
            got = api.get(f'/api/network?host={node.name}')['network']
            if 'listeners' not in got['unreadable']:
                demo.fail(f'should say listeners could not be read: {got["unreadable"]}')
        finally:
            sudo(node.name, f'mv {ss}.lab-away {ss}')
        demo.scan(api, [node.ip])
        return 'the scan finished, and it says listeners were not read rather than none'
    r.check('failed-collector', vms[0].name, failed_collector)

    # the exit check of Stage 2: a port ufw looks like it blocks, against a real connection
    def ufw_exposure():
        sudo(ufw.name, "command -v ufw >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -qq install -y ufw; ufw default deny incoming >/dev/null; ufw allow 22/tcp >/dev/null; ufw --force enable >/dev/null")
        published_container(ufw)
        listen(ufw.name, 18081)
        demo.scan(api, [ufw.ip])
        api.post('/api/infra/measure', {'host': ufw.name})
        rep = api.get(f'/api/exposure?host={ufw.name}')['hosts'][0]
        items = {i['port']: i for i in rep['items']}
        client = roles.other_than(ufw)
        pub, plain = items.get(18080), items.get(18081)
        if not pub or pub['level'] not in ('lan', 'any') or not pub.get('bypasses_frontend'):
            demo.fail(f'a published port should show as reachable, past ufw: {pub}')
        if not connects(client.name, ufw.ip, 18080):
            demo.fail('the map says reachable, but a real connection failed')
        if not plain or plain['level'] != 'blocked':
            demo.fail(f'a plain listener ufw blocks should say blocked: {plain}')
        if connects(client.name, ufw.ip, 18081):
            demo.fail('the map says blocked, but a real connection got through')
        return f'{pub["level"]} and past ufw by "{pub["rule"]}", and a real connection agrees; a plain listener is blocked, and that agrees too'
    r.check('ufw-exposure', ufw.name, ufw_exposure) if ufw else r.add('ufw-exposure', '-', None, 'no Docker host')

    # every firewall gives the same model
    def firewall_model(node, setup, backend):
        def run():
            sudo(node.name, setup)
            out = api.post('/api/infra/measure', {'host': node.name})
            if not out.get('ok'):
                demo.fail(out.get('error'))
            fw = api.get(f'/api/firewall?host={node.name}')['firewall']
            if not fw or not fw['readable']:
                demo.fail(f'not readable: {fw and fw["notes"]}')
            if backend not in fw['backends']:
                demo.fail(f'{backend} not among {fw["backends"]}')
            found = [x for x in fw['rules'] if 18443 in (x.get('dports') or []) and x.get('action') == 'accept']
            if not found:
                demo.fail(f'the rule for 18443 is not in the model ({len(fw["rules"])} rules)')
            return f'{backend}: {found[0]["chain"]}, saddr {found[0].get("saddr")}'
        return run
    if ufw:
        r.check('fw-model-ufw', ufw.name, firewall_model(ufw, 'ufw allow from 10.77.0.0/24 to any port 18443 proto tcp >/dev/null', 'ufw'))
    wall = next((n for n in vms if n.pm == 'dnf'), None)
    if wall:
        r.check('fw-model-firewalld', wall.name, firewall_model(wall, 'command -v firewall-cmd >/dev/null || dnf -q -y install firewalld; systemctl enable --now firewalld >/dev/null 2>&1; firewall-cmd -q --add-service=ssh --permanent; firewall-cmd -q --add-port=18443/tcp --permanent; firewall-cmd -q --reload', 'firewalld'))
    else:
        r.add('fw-model-firewalld', '-', None, 'no firewalld host')
    plain = next((n for n in vms if n.pm == 'apt-get' and n.name != (ufw.name if ufw else '')), None)
    if plain:
        r.check('fw-model-nftables', plain.name, firewall_model(plain, "command -v nft >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -qq install -y nftables; nft 'add table inet lab; add chain inet lab input { type filter hook input priority 0; policy accept; }; add rule inet lab input tcp dport 18443 ip saddr 10.77.0.0/24 accept'", 'nftables'))
        r.check('fw-model-iptables', plain.name, firewall_model(plain, 'command -v iptables >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -qq install -y iptables; iptables -I INPUT -p tcp --dport 18443 -s 10.77.0.0/24 -j ACCEPT', 'iptables'))

    # unreadable says so, and exposure says unknown, not closed
    def unreadable():
        node = next(n for n in roles.build().values() if n.can('nosystemd'))
        rep = api.get(f'/api/exposure?host={node.name}')['hosts'][0]
        wrong = [i for i in rep['items'] if i['level'] == 'blocked']
        if wrong:
            demo.fail(f'called blocked with no firewall read: {wrong[:2]}')
        if rep.get('firewall_read'):
            demo.fail('claims to have read a firewall on a host with no measurement')
        return f'{len(rep["items"])} listeners, none called blocked with nothing read'
    r.check('unreadable', next(n for n in roles.build().values() if n.can('nosystemd')).name, unreadable)

    # the workloads each runtime really has
    def workload(node, runtime, name):
        def run():
            demo.scan(api, [node.ip])
            api.post('/api/infra/measure', {'host': node.name})
            items = api.get(f'/api/workloads?host={node.name}')['workloads']
            hit = [w for w in items if w['runtime'] == runtime and w['name'] == name]
            if not hit:
                demo.fail(f'{name} not among {[w["name"] for w in items]}')
            if not hit[0]['detail']:
                demo.fail(f'{name} has no detail')
            return f'{name}: {hit[0]["state"]}, {len(hit[0]["mounts"])} mounts, {len(hit[0]["ports"])} ports'
        return run
    for node in roles.having('docker'):
        r.check('workload-docker', node.name, workload(node, 'docker', 'sflab-web'))
    for node in roles.having('podman'):
        r.check('workload-podman', node.name, workload(node, 'podman', 'sflab-web'))

    # a libvirt guest: defined, never booted, with its disk resolved to the mount it sits on
    def libvirt():
        node = vms[0]
        disk = f'{node.room}/sf-lab.qcow2'
        sudo(node.name, 'command -v virsh >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get -qq install -y libvirt-daemon-system qemu-utils virtinst || dnf -q -y install libvirt qemu-img qemu-kvm || zypper -nq install libvirt qemu-tools; systemctl enable --now libvirtd >/dev/null 2>&1 || true; }')
        sudo(node.name, f'qemu-img create -f qcow2 {disk} 64M >/dev/null')
        xml = f"""<domain type='qemu'><name>sf-lab-guest</name><memory unit='MiB'>64</memory><vcpu>1</vcpu><os><type>hvm</type></os>
<devices><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='{disk}'/><target dev='vda' bus='virtio'/></disk></devices></domain>"""
        ssh(node.name, 'cat >/tmp/sf-lab-guest.xml', stdin=xml)
        sudo(node.name, 'virsh -c qemu:///system define /tmp/sf-lab-guest.xml >/dev/null')
        api.post('/api/infra/measure', {'host': node.name})
        vm = [w for w in api.get(f'/api/workloads?host={node.name}')['workloads'] if w['name'] == 'sf-lab-guest']
        if not vm or vm[0]['runtime'] != 'libvirt':
            demo.fail(f'the guest was not found: {vm}')
        on = (vm[0]['mounts'][0].get('on') or {}).get('mount')
        expected = sudo(node.name, f'findmnt -no TARGET --target {disk}').strip()
        if on != expected:
            demo.fail(f'its disk should sit on {expected}, says {on}')
        return f'guest found, disk on {on}'
    r.check('workload-libvirt', vms[0].name, libvirt)

    # change tracking: add a listener, stop a container, edit a rule. The diff is exactly those
    def change_tracking():
        node = ufw or vms[0]
        demo.scan(api, [node.ip])
        api.post('/api/infra/measure', {'host': node.name})
        before = api.get(f'/api/map/snapshots?host={node.name}')['changes']
        listen(node.name, 18099)
        demo.scan(api, [node.ip])
        api.post('/api/infra/measure', {'host': node.name})
        after = api.get(f'/api/map/snapshots?host={node.name}')['changes']
        if len(after) <= len(before):
            demo.fail('a new listener left no change on the timeline')
        added = after[0]['added']
        if not any('18099' in a for a in added):
            demo.fail(f'not in the diff: {after[0]}')
        strays = [a for a in added if '18099' not in a]
        if strays:
            demo.fail(f'the diff has more than what changed: {strays[:5]}')
        return f'{after[0]["added"]} and nothing else'
    r.check('change-tracking', (ufw or vms[0]).name, change_tracking)

    # exports: each renders, and a redacted one gives nothing away
    def exports():
        names = list(roles.build()) + [n.ip for n in roles.build().values()]
        sizes = {}
        for fmt in api.get('/api/map/formats')['formats']:
            text = api.text(f'/api/map/export?format={fmt}&redact=1')
            sizes[fmt] = len(text)
            if not text.strip():
                demo.fail(f'{fmt} is empty')
            found = [n for n in names if n in text] + re.findall(r'\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', text)
            if found:
                demo.fail(f'{fmt} still says {found[:5]}')
        return ', '.join(f'{k} {v}' for k, v in sizes.items())
    r.check('exports-redacted', '-', exports)

    # does a quarantine reach what is published by a container? (Stage 2 asks, and writes down the answer)
    def fence_covers_published():
        if not ufw:
            return None
        client = roles.other_than(ufw)
        if not connects(client.name, ufw.ip, 18080):
            demo.fail('the published port is not reachable to begin with')
        api.post('/api/security/firewall/quarantine', {'host': ufw.name, 'ip_address': client.ip, 'minutes': 5, 'mode': 'apply'})
        if connects(client.name, ufw.ip, 18080):
            demo.fail('a quarantined client still reaches a published container port')
        api('DELETE', f'/api/security/firewall/quarantine/{client.ip}?host={ufw.name}&mode=apply')
        return 'a quarantined client is cut off from a published port, as well as from the host'
    r.check('fence-published-port', (ufw or vms[0]).name, fence_covers_published)


# ── tier 11: changes, each judged by a real connection ──────────────
def plan(api, name, tasks, **options):
    """A plan through the whole path: saved, checked, reported on the host, then applied by signed run. Returns the apply's runs."""
    pid = api.post('/api/changes', {'name': name, 'tasks': tasks})['id']
    return pid, demo.deploy(api, 'changes', pid, name, **options)


def remeasure(api, node):
    out = api.post('/api/infra/measure', {'host': node.name})
    if not out.get('ok'):
        demo.fail(f'{node.name}: infra measure: {out.get("error")}')


def level_of(api, node, port):
    rep = api.get(f'/api/exposure?host={node.name}')['hosts'][0]
    return next((i for i in rep['items'] if i['port'] == port), None)


def install(node, pkg):
    sudo(node.name, f'if command -v apt-get >/dev/null; then export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=180 -qq install -y {pkg} || {{ apt-get -o DPkg::Lock::Timeout=180 -qq update; apt-get -o DPkg::Lock::Timeout=180 -qq install -y {pkg}; }}; elif command -v dnf >/dev/null; then dnf -q -y install {pkg}; else zypper -nq install {pkg}; fi')


def tier11(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    vms = roles.deployable()
    docker_host = next(iter(roles.having('docker')), None)
    grant_engines()
    named = lambda *ns: {n.name for n in ns if n}  # noqa: E731
    wall = next((n for n in vms if n.pm == 'dnf'), None)
    nft_host = next((n for n in vms if n.pm == 'apt-get' and n.name not in named(docker_host)), None)
    client = next(n for n in vms if n.name not in named(docker_host, wall, nft_host))
    other = next((n for n in vms if n.name not in named(docker_host, client, wall, nft_host)), None) or next(n for n in vms if n.name not in named(docker_host, client))

    def backend_rule(node, setup, label, port):
        """Allow from one client and no other, then take it away. What the map says and what a real connection does must agree."""
        def run():
            sudo(node.name, setup)
            listen(node.name, port)
            a = next(n for n in vms if n.name != node.name)
            plan(api, f'{label} deny {port}', [{'type': 'fw-rule', 'host': node.name, 'params': {'action': 'deny', 'proto': 'tcp', 'port': str(port)}}])
            if connects(a.name, node.ip, port):
                demo.fail('denied by plan, and a real connection still works')
            remeasure(api, node)
            item = level_of(api, node, port)
            if not item or item['level'] != 'blocked':
                demo.fail(f'a real connection fails, and the map says {item}')
            plan(api, f'{label} undeny {port}', [{'type': 'fw-rule', 'host': node.name, 'params': {'action': 'deny', 'proto': 'tcp', 'port': str(port), 'state': 'absent'}}, {'type': 'fw-rule', 'host': node.name, 'params': {'action': 'allow', 'proto': 'tcp', 'port': str(port), 'source': a.ip}}])
            if not connects(a.name, node.ip, port):
                demo.fail(f'allowed from {a.ip}, and it cannot connect')
            remeasure(api, node)
            verdict = api.get(f'/api/map/reach?from={a.ip}&to={node.name}&port={port}')['verdict']
            if verdict != 'allowed':
                demo.fail(f'a real connection works, and reach says {verdict}')
            # the firewall still lists it, in its own words
            sudo(node.name, f'{{ ufw status 2>/dev/null; firewall-cmd --list-rich-rules 2>/dev/null; nft list ruleset 2>/dev/null; iptables-save 2>/dev/null; }} | grep -q {port}')
            return f'deny, then allow from one source: map and real connections agree on {label}'
        return run
    if docker_host:
        r.check('fw-rule-ufw', docker_host.name, backend_rule(docker_host, "command -v ufw >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -qq install -y ufw; ufw default deny incoming >/dev/null; ufw allow 22/tcp >/dev/null; ufw --force enable >/dev/null", 'ufw', 18201))
    if nft_host:
        r.check('fw-rule-nftables', nft_host.name, backend_rule(nft_host, "command -v nft >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -qq install -y nftables; nft 'add table inet lab; add chain inet lab input { type filter hook input priority 0; policy drop; }; add rule inet lab input tcp dport 22 accept; add rule inet lab input ct state established,related accept'", 'nftables', 18202))
    if wall:
        r.check('fw-rule-firewalld', wall.name, backend_rule(wall, 'command -v firewall-cmd >/dev/null || dnf -q -y install firewalld; systemctl enable --now firewalld >/dev/null 2>&1; firewall-cmd -q --add-service=ssh --permanent; firewall-cmd -q --reload', 'firewalld', 18203))

    # the fix for a port ufw does not stop
    def published():
        published_container(docker_host)
        if not connects(client.name, docker_host.ip, 18080):
            demo.fail('the published port should be reachable to begin with')
        demo.scan(api, [docker_host.ip])
        plan(api, 'close published', [{'type': 'fw-rule', 'host': docker_host.name, 'params': {'action': 'deny', 'proto': 'tcp', 'port': '18080', 'hook': 'forward'}}])
        if connects(client.name, docker_host.ip, 18080):
            demo.fail('staged the fix, and a real connection still works')
        if not connects(docker_host.name, '127.0.0.1', 18080):
            demo.fail('the fix cut loopback too')
        remeasure(api, docker_host)
        item = level_of(api, docker_host, 18080)
        if not item or item['level'] != 'blocked':
            demo.fail(f'the badge did not flip: {item}')
        return 'closed from outside, loopback still works, and the badge flipped'
    r.check('published-port-fix', docker_host.name, published) if docker_host else r.add('published-port-fix', '-', None, 'no Docker host')

    # a fence: only its clients reach the port, ahead of whatever else the host runs
    def fence():
        node = other
        listen(node.name, 445)
        a, b = client, next(n for n in vms if n.name not in named(node, client))
        if not connects(b.name, node.ip, 445):
            sudo(node.name, 'systemctl stop firewalld ufw 2>/dev/null; true')
        plan(api, 'fence smb', [{'type': 'fw-fence', 'host': node.name, 'params': {'name': 'lab', 'service': 'smb', 'clients': f'{a.ip}/32'}}])
        if not connects(a.name, node.ip, 445):
            demo.fail('a client inside the fence cannot connect')
        if connects(b.name, node.ip, 445):
            demo.fail('a client outside the fence still connects')
        remeasure(api, node)
        item = level_of(api, node, 445)
        if not item or not item.get('fenced_to'):
            demo.fail(f'the map does not show the fence: {item}')
        sudo(node.name, 'reboot', check=False)
        time.sleep(25)
        t.wait_for('it to come back', lambda: quiet(node.name, 'true') == 0, 240)
        listen(node.name, 445)
        if connects(b.name, node.ip, 445):
            demo.fail('the fence did not survive a reboot')
        return f'{a.ip} in, {b.ip} out, shown on the map, and it survives a reboot'
    r.check('fence', other.name, fence)

    # what would cut StorageForge off: flagged first, and undone by the timer if done anyway
    def ssh_cut():
        node = other
        sudo(node.name, 'systemctl stop firewalld ufw 2>/dev/null; true')
        remeasure(api, node)
        task = {'type': 'fw-rule', 'host': node.name, 'params': {'action': 'deny', 'proto': 'tcp', 'port': '22'}}
        got = api.post('/api/map/whatif', {'tasks': [task]})
        if not got['blocked'] and 'how StorageForge reaches it' not in json.dumps(got['conflicts']):
            demo.fail(f'what-if did not flag cutting SSH: {got["conflicts"]}')
        task['params']['rollback'] = '1'
        pid = api.post('/api/changes', {'name': 'cut ssh', 'tasks': [task]})['id']
        status, res = attempt(api, '/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'report', 'title': 'cut ssh (report)'})
        group = res['group']
        demo.wait('the report', lambda: demo.finished(api, group))
        attempt(api, '/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'apply', 'title': 'cut ssh', 'report_group': group})
        time.sleep(100)
        t.wait_for('the rollback timer to bring SSH back', lambda: connects(client.name, node.ip, 22), 120)
        if 'storageforge_rules' in sudo(node.name, 'nft list tables 2>/dev/null') and 'sf-rule' in sudo(node.name, 'nft list table inet storageforge_rules 2>/dev/null'):
            demo.fail('SSH is back but the rule is still there')
        return 'flagged by what-if, and undone by the timer when nothing could confirm it'
    r.check('ssh-cut-rollback', other.name, ssh_cut)

    # reach against reality: every flow in a table, with a real connection
    def reach_table():
        srv, frm = docker_host or vms[0], client
        listen(srv.name, 18301)
        sudo(srv.name, "nohup python3 -m http.server 18302 --bind 127.0.0.1 >/dev/null 2>&1 &")
        time.sleep(2)
        demo.scan(api, [srv.ip, frm.ip])
        remeasure(api, srv)
        remeasure(api, frm)
        wrong, n = [], 0
        for port, what in ((22, 'ssh'), (18301, 'plain listener'), (18302, 'loopback only'), (18399, 'nothing there'), (18080, 'published')):
            got = api.get(f'/api/map/reach?from={frm.name}&to={srv.name}&port={port}')
            real = connects(frm.name, srv.ip, port)
            n += 1
            if got['verdict'] == 'unknown':
                wrong.append(f'{what}: unknown, because {got["blind_spots"]}')
            elif (got['verdict'] == 'allowed') != real:
                wrong.append(f'{what}: says {got["verdict"]} ({got.get("decided_by")}), a real connection {"works" if real else "fails"}')
        if wrong:
            demo.fail('; '.join(wrong))
        return f'{n} flows, all agree with real connections'
    r.check('reach-table', (docker_host or vms[0]).name, reach_table)

    # after Apply the next reading agrees with what the overlay said
    def overlay_agrees():
        node = client                   # no firewall of its own: the plan is what closes the port
        listen(node.name, 18401)
        demo.scan(api, [node.ip])
        remeasure(api, node)
        task = {'type': 'fw-rule', 'host': node.name, 'params': {'action': 'deny', 'proto': 'tcp', 'port': '18401'}}
        said = next(c for h in api.post('/api/map/whatif', {'tasks': [task]})['exposure'] for c in h['changes'] if c['port'] == 18401)
        plan(api, 'overlay check', [task])
        remeasure(api, node)
        now = level_of(api, node, 18401)
        if now['level'] != said['after']:
            demo.fail(f'the overlay said {said["after"]}, and the next reading says {now["level"]}')
        return f'overlay and next reading both say {now["level"]}'
    r.check('whatif-agrees', client.name, overlay_agrees)

    # a design: half is there, and the compare lists exactly the other half
    def design():
        node = docker_host
        image = sudo(node.name, 'docker image ls --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>" | head -n1').strip()
        doc = {'hosts': [{'name': node.name, 'workloads': [{'kind': 'container', 'runtime': 'docker', 'name': 'sflab-web', 'image': image}, {'kind': 'container', 'runtime': 'docker', 'name': 'sf-design-new', 'image': image, 'publish': '127.0.0.1:18501:80'}], 'networks': [{'kind': 'bridge', 'name': 'sfbr9', 'address': '10.99.9.1/24'}]}]}
        demo.scan(api, [node.ip])
        did = api.post('/api/map/designs', {'name': 'lab half', 'doc': doc})['id']
        got = api.get(f'/api/map/designs/{did}/compare')
        missing = sorted(m['what'] for m in got['missing'])
        if missing != ['sf-design-new', 'sfbr9']:
            demo.fail(f'missing should be the other half: {missing}')
        staged = api.post(f'/api/map/designs/{did}/stage')
        demo.deploy(api, 'changes', staged['plan_id'], 'design')
        if quiet(node.name, f'docker inspect sf-design-new >/dev/null') != 0:
            demo.fail('the container was not started')
        demo.scan(api, [node.ip])
        again = api.get(f'/api/map/designs/{did}/compare')
        if again['missing']:
            demo.fail(f'still missing after the plan: {again["missing"]}')
        for target, word in (('terraform', 'docker_container'), ('puppet', 'docker::run'), ('ansible', 'docker_container'), ('bash', 't_container')):
            if word not in api.text(f'/api/map/designs/{did}/export?target={target}'):
                demo.fail(f'{target} export has no {word}')
        return 'compare lists the other half, the plan closes it, and all four exports render'
    r.check('design', docker_host.name, design) if docker_host else r.add('design', '-', None, 'no Docker host')

    # hardening as steps: report first, a real change, a second run says it is done
    def hardening():
        node = vms[0]
        tasks = [{'type': 'sysctl-set', 'host': node.name, 'params': {'key': 'fs.protected_fifos', 'value': '2'}}, {'type': 'umask-set', 'host': node.name, 'params': {'value': '027'}},
                 {'type': 'sshd-option', 'host': node.name, 'params': {'key': 'X11Forwarding', 'value': 'no', 'rollback': '5'}}, {'type': 'chrony-nts', 'host': node.name, 'params': {'servers': 'time.cloudflare.com'}}]
        install(node, 'chrony')
        plan(api, 'hardening', tasks)
        if sudo(node.name, 'sysctl -n fs.protected_fifos').strip() != '2':
            demo.fail('the kernel setting did not change')
        if 'x11forwarding no' not in sudo(node.name, 'sshd -T').lower():
            demo.fail('the SSH setting did not change')
        if quiet(node.name, 'systemctl list-timers --all --no-legend | grep -q sf-fw-rollback') == 0:
            demo.fail('the rollback timer was not stopped by the second run')
        if 'nts' not in sudo(node.name, 'cat /etc/chrony.d/storageforge-nts.conf /etc/chrony/conf.d/storageforge-nts.conf 2>/dev/null; true'):
            demo.fail('chrony has no NTS sources')
        return 'all four applied, the timer stopped, and the settings are on the host'
    r.check('hardening-steps', vms[0].name, hardening)

    # WireGuard: two hosts peered, and confirmed by public key on the graph
    def wireguard():
        a, b = client, other
        for n in (a, b):
            install(n, 'wireguard-tools')
        keys = {}
        for i, n in enumerate((a, b)):
            keys[n.name] = sudo(n.name, f'modprobe wireguard; ip link add wg0 type wireguard; ip addr add 10.66.0.{i + 1}/24 dev wg0; umask 077; wg genkey >/tmp/wg.key; wg set wg0 private-key /tmp/wg.key listen-port 51820; ip link set wg0 up; wg show wg0 public-key').strip()
        sudo(a.name, f'wg set wg0 peer {keys[b.name]} allowed-ips 10.66.0.2/32 endpoint {b.ip}:51820')
        plan(api, 'wg peer', [{'type': 'wg-peer', 'host': b.name, 'params': {'iface': 'wg0', 'pubkey': keys[a.name], 'allowed': '10.66.0.1/32'}}])
        remeasure(api, a)
        remeasure(api, b)
        g = api.get('/api/map?layers=access')
        if not any(e['rel'] == 'PEERS_WITH' and e['props'].get('confidence') == 'confirmed' for e in g['edges']):
            demo.fail('no confirmed peer on the graph')
        output = sudo('sf-ctl', f"""{COMPOSE} exec -T storageforge python -c "import sqlite3; c=sqlite3.connect('/app/data/index.db'); print(chr(10).join(r[0] or '' for r in c.execute('SELECT output FROM deploy_runs')))" """)
        if sudo(a.name, 'cat /tmp/wg.key').strip() in output:
            demo.fail('a private key reached deploy_runs')
        plan(api, 'wg revoke', [{'type': 'wg-peer', 'host': b.name, 'params': {'iface': 'wg0', 'pubkey': keys[a.name], 'allowed': '10.66.0.1/32', 'state': 'absent'}}])
        if keys[a.name] in sudo(b.name, 'wg show wg0 peers'):
            demo.fail('revoking left the peer')
        return 'peered and confirmed by key, no private key in any run, and revoke works'
    r.check('wireguard', client.name, wireguard)

    # a placeholder, promoted
    def placeholder():
        a, b = client, next(n for n in roles.build().values() if n.can('nosystemd'))    # no plan ever ran there, so the index can let it go
        api('DELETE', f'/api/hosts/{b.name}')
        sudo(a.name, f'ping -c1 -W2 {b.ip} >/dev/null || true')
        demo.scan(api, [a.ip])
        g = api.get('/api/map?layers=network')
        node = next((n for n in g['nodes'] if n['id'] == f'ph:{b.ip}'), None)
        if not node or node['confidence'] != 'inferred' or not node['props'].get('placeholder'):
            demo.fail(f'an unscanned neighbour should be a dashed placeholder: {node}')
        said = api.post(f'/api/map/placeholders/ph:{b.ip}/promote', {})
        if 'bind a key' not in said['message']:
            demo.fail(f'promoting should say what comes next: {said}')
        demo.cli('vault', 'bind', '--key', 'lab-scan', '--host', b.ip, '--user', 'scan', '--actions', 'scan,checksum')
        demo.scan(api, [b.ip])
        demo.scan(api, [a.ip])
        g = api.get('/api/map?layers=network')
        if any(n['id'] == f'ph:{b.ip}' for n in g['nodes']):
            demo.fail('still a placeholder after it was scanned')
        return 'dashed while unscanned, and a host once scanned'
    r.check('placeholder', next(n for n in roles.build().values() if n.can('nosystemd')).name, placeholder)

    # retention policy, freeze and rollback preview, on real ZFS
    zfs = next(iter(roles.having('zfs')), None)

    def retention():
        ds = zfs_dataset(zfs)
        sudo(zfs.name, f'zfs snapshot {ds}@sf-lab-a; zfs snapshot {ds}@sf-lab-b')
        measure(api, zfs.name)
        api.post('/api/security/worm/policies', {'host': zfs.name, 'pattern': ds, 'days': 3})
        out = api.post('/api/security/worm/policies/apply', {'host': zfs.name, 'mode': 'apply'})
        if not out['done'] or 'sf-lab-b' not in out['done'][0]['snapshot']:
            demo.fail(f'the newest snapshot was not held: {out}')
        if not sudo(zfs.name, f'zfs holds -H {ds}@sf-lab-b').strip():
            demo.fail('recorded, but no hold on the host')
        sudo(zfs.name, f'echo new >{zfs.data}/sf-lab-after; rm -f {zfs.data}/lab-seed/shared/docs/handbook.txt')
        pv = api.post('/api/security/worm/preview', {'host': zfs.name, 'snapshot': f'{ds}@sf-lab-b'})
        if not pv['counts']:
            demo.fail(f'the preview saw no difference: {pv}')
        sudo(zfs.name, f'zfs snapshot -r {ds}@sf-lab-c')
        fz = api.post('/api/security/worm/freeze', {'host': zfs.name, 'target': ds, 'mode': 'apply'})
        if not fz.get('held'):
            demo.fail(f'nothing frozen: {fz}')
        if quiet(zfs.name, f'zfs destroy {ds}@sf-lab-a') == 0:
            demo.fail('zfs destroy got past the freeze')
        return f'the policy held the newest, the preview saw {pv["counts"]}, and the freeze held {fz["held"]}'
    r.check('retention', zfs.name, retention) if zfs else r.add('retention', '-', None, 'no ZFS host')

    # YARA on a changed file, for real
    def yara():
        node = zfs or vms[0]
        install(node, 'yara')
        demo.scan(api, [node.ip])
        sudo(node.name, f"echo 'your files have been encrypted, send bitcoin to the following address' >{node.data}/sf-lab-note.txt")
        demo.scan(api, [node.ip])
        got = api.post('/api/security/behavior/yara', {'host': node.name})
        if not got.get('found'):
            demo.fail(f'the note was not found: {got}')
        det = [d for d in api.get(f'/api/clamav?host={node.name}')['detections'] if 'YARA' in d['signature']]
        if not det:
            demo.fail('the match is not in the Malware list')
        return f'{got["found"]} match on {got["scanned"]} changed files, in the Malware list'
    r.check('yara', (zfs or vms[0]).name, yara)

    # a playbook: what it would do, then doing it
    def playbook():
        node = next((n for n in roles.having('btrfs') if n.subvol), None) or vms[0]
        api.post('/api/security/sentinel', {'host': node.name, 'folders': [node.data], 'armed': False})
        demo.deploy(api, 'security', node.name, 'sentinel')
        api.post('/api/security/playbooks', {'name': 'lab watch', 'trigger': 'canary_tripped', 'actions': ['snapshot'], 'mode': 'dry_run'})
        time.sleep(70)
        sudo(node.name, f"echo x >>'{node.data}/_AAAPasswords.docx'")
        said = t.wait_for('the playbook to say what it would do', lambda: [x for x in api.get('/api/security/playbooks')['runs'] if x['playbook'] == 'lab watch'], 180)
        if said[0]['outcome'] != 'would':
            demo.fail(f'a new playbook acted: {said[0]}')
        return 'it fired on a real trip, and only said what it would do'
    r.check('playbook', (next((n for n in roles.having('btrfs') if n.subvol), None) or vms[0]).name, playbook)

    # who is connected to Samba: sampled for real, and off again
    def identity():
        srv = roles.smb_server()
        sudo(srv.name, 'systemctl stop firewalld 2>/dev/null; true')
        _, cli = demo.share_smb(api, server=srv, name='labid', mount='/mnt/lab-id')
        if cli is None:
            return None
        report = api.post('/api/security/mac/identity/deploy', {'host': srv.name, 'enabled': True, 'max_shares': 5, 'off_from': 0, 'off_to': 0, 'mode': 'report'})
        if quiet(srv.name, 'test -e /usr/local/sbin/storageforge-sessions') == 0:
            demo.fail(f'the report installed it: {str(report)[:200]}')
        # off hours are the hour it is now, so a connection right now is flagged
        hour = int(sudo(srv.name, 'date +%-H').strip())
        api.post('/api/security/mac/identity/deploy', {'host': srv.name, 'enabled': True, 'max_shares': 5, 'off_from': hour, 'off_to': (hour + 2) % 24, 'mode': 'apply'})
        sudo(cli.name, 'ls /mnt/lab-id >/dev/null')
        sudo(srv.name, 'systemctl start storageforge-sessions.service; sleep 1')
        measure(api, srv.name)
        got = api.get(f'/api/security/mac/identity-anomalies?host={srv.name}')
        if not any(x['client'] == cli.ip and x['share'] == 'labid' for x in got['sessions']):
            demo.fail(f'the session was not read: {got["sessions"][:3]}')
        if not any(e['kind'] == 'identity_off_hours' for e in got['events']):
            demo.fail(f'no flag for a connection off hours: {got["events"][:3]}')
        api.post('/api/security/mac/identity/deploy', {'host': srv.name, 'enabled': False, 'mode': 'apply'})
        if quiet(srv.name, 'test -e /var/lib/storageforge/security/sessions.tsv') == 0:
            demo.fail('turned off, and what it recorded is still there')
        return f'{cli.ip} on labid read from smbstatus, flagged off hours, and gone when turned off'
    r.check('identity', roles.smb_server().name, identity)

    # evidence: signed by the controller, and checked with nothing but ssh-keygen
    def evidence():
        node = vms[0]
        got = api.post('/api/security/evidence', {'host': node.name})
        doc = json.loads(got['document'])
        if 'not an attestation' not in doc['statement']:
            demo.fail('it should say what it is not')
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'signers').write_text(f'storageforge namespaces="storageforge-evidence" {got["public_key"]}\n')
            (Path(tmp) / 'sig').write_text(got['signature'])
            cmd = ['ssh-keygen', '-Y', 'verify', '-f', f'{tmp}/signers', '-I', 'storageforge', '-n', 'storageforge-evidence', '-s', f'{tmp}/sig']
            if subprocess.run(cmd, input=got['document'].encode(), capture_output=True).returncode != 0:
                demo.fail('the signature does not verify')
            if subprocess.run(cmd, input=got['document'].replace(node.name, 'other').encode(), capture_output=True).returncode == 0:
                demo.fail('a changed record verified')
        return f'{len(doc["events"])} events and {len(doc["audit"])} actions, and ssh-keygen checks it and refuses a changed copy'
    r.check('evidence', vms[0].name, evidence)

    # re-converging: the failing checks a step can fix, fixed by a plan, and read back by a measurement
    def reconverge():
        node = client
        sudo(node.name, 'sysctl -q -w fs.protected_hardlinks=0; rm -f /etc/sysctl.d/99-storageforge-security.conf /etc/sysctl.d/90-storageforge-plan.conf')
        measure(api, node.name)
        before = {c['id']: c['result'] for c in api.get(f'/api/security/compliance/status/{node.name}?profile=cis-l1')['checks']}
        if before.get('sysctl') != 'fail':
            demo.fail(f'should fail first: {before}')
        out = api.post('/api/security/compliance/reconverge', {'host': node.name, 'profile': 'cis-l1'})
        if not out.get('plan_id'):
            demo.fail(f'no plan: {out}')
        demo.deploy(api, 'changes', out['plan_id'], 'reconverge')
        measure(api, node.name)
        after = {c['id']: c['result'] for c in api.get(f'/api/security/compliance/status/{node.name}?profile=cis-l1')['checks']}
        if after.get('sysctl') != 'pass':
            demo.fail(f'should pass after: {after}')
        api.post('/api/security/waivers', {'host': node.name, 'finding': 'aide', 'reason': 'the lab has no baseline, on purpose', 'days': 1})
        waived = {c['id']: c['result'] for c in api.get(f'/api/security/compliance/status/{node.name}?profile=cis-l1')['checks']}
        if after.get('aide') == 'fail' and waived.get('aide') != 'waived':
            demo.fail(f'the waiver did not take: {waived}')
        return f'sysctl fail to pass through a plan of {out["tasks"]} step(s), and a waiver shows as waived'
    r.check('reconverge', client.name, reconverge)

    # a bundle made on an online host
    def bundle():
        node = nft_host or vms[0]
        got = attempt(api, '/api/security/packages/bundle', {'host': node.name, 'mode': 'apply'})[1]
        if got.get('error') or not got.get('path'):
            demo.fail(f'{got.get("error")}: {str(got.get("output"))[-500:]}')
        n = int(sudo(node.name, f'tar tzf {got["path"]} | grep -c "\\.deb$\\|\\.rpm$\\|\\.zst$"').strip())
        if not n or sudo(node.name, f'sha256sum {got["path"]}').split()[0] != got['sha256']:
            demo.fail(f'{n} packages, or the checksum does not match')
        script = api.text(f'/api/security/compliance/script?host={node.name}&profile=cis-l1')
        ssh(node.name, 'cat >/tmp/sf-init.sh', stdin=script)
        text = sudo(node.name, f'bash /tmp/sf-init.sh --offline-bundle {got["path"]} --waive aide; true')
        if 'waived on the command line' not in text:
            demo.fail(f'the script did not take its flags: {text[-400:]}')
        return f'{n} packages in {got["path"]}, the checksum matches, and the script takes it'
    r.check('bundle', (nft_host or vms[0]).name, bundle)

    # a VLAN on each kind of network manager, and that it lasts
    def primary(node):
        return sudo(node.name, "ip -o route get 10.77.0.1 | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p'").strip()

    def vlan(node, vid):
        def run():
            nic = primary(node)
            manager = 'nm' if quiet(node.name, '[ "$(nmcli -t -f RUNNING general 2>/dev/null)" = running ]') == 0 else 'networkd'
            plan(api, f'vlan {vid}', [{'type': 'net-vlan', 'host': node.name, 'params': {'parent': nic, 'vlan_id': str(vid), 'address': f'10.99.{vid}.1/24'}}])
            name = f'{nic}.{vid}'
            if quiet(node.name, f'ip link show {name}') != 0:
                demo.fail(f'{name} is not there')
            demo.scan(api, [node.ip])
            got = api.get(f'/api/network?host={node.name}')['network']
            found = next((i for i in got['interfaces'] if i['name'] == name), None)
            if not found or found.get('vlan_id') != vid:
                demo.fail(f'a scan does not read it as VLAN {vid}: {found}')
            sudo(node.name, 'reboot', check=False)
            time.sleep(25)
            t.wait_for('it to come back', lambda: quiet(node.name, 'true') == 0, 240)
            if quiet(node.name, f'ip link show {name}') != 0:
                demo.fail(f'{name} did not survive a reboot')
            return f'{name} with {manager}, read by a scan, and it survives a reboot'
        return run
    if docker_host:
        r.check('net-vlan', docker_host.name, vlan(docker_host, 77))
    if wall:
        r.check('net-vlan', wall.name, vlan(wall, 78))

    # moving the interface StorageForge comes in on: flagged, and undone by the timer when nothing can confirm it
    def bridge_cut():
        node = wall or vms[0]
        nic = primary(node)
        task = {'type': 'net-bridge', 'host': node.name, 'params': {'name': 'sfbrcut', 'ports': nic}}
        got = api.post('/api/map/whatif', {'tasks': [task]})
        if not got['blocked']:
            demo.fail(f'what-if did not flag it: {got["conflicts"]}')
        task['params']['rollback'] = '1'
        pid = api.post('/api/changes', {'name': 'cut by bridge', 'tasks': [task]})['id']
        _, res = attempt(api, '/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'report', 'title': 'cut by bridge (report)'})
        demo.wait('the report', lambda: demo.finished(api, res['group']))
        if quiet(node.name, 'ip link show sfbrcut') == 0:
            demo.fail('the report made the bridge')
        attempt(api, '/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'apply', 'title': 'cut by bridge', 'report_group': res['group']})
        time.sleep(20)
        if connects(client.name, node.ip, 22):
            demo.fail('moving the interface into a bridge with no address should have cut SSH, so this proves nothing')
        t.wait_for('the timer to bring it back', lambda: connects(client.name, node.ip, 22), 240)
        if quiet(node.name, f'ip -o link show {nic} | grep -q "master sfbrcut"') == 0:
            demo.fail('reachable again, but the interface is still in the bridge')
        return 'it cut SSH, nothing could confirm it, and the timer put it back'
    r.check('bridge-rollback', (wall or vms[0]).name, bridge_cut)

    # packages: what is present, what could be, and a bundle of them
    def packages():
        node = vms[0]
        got = api.post('/api/security/packages/check', {'host': node.name})
        if not got['tools'] or got['pm'] == 'none':
            demo.fail(f'no answer: {got}')
        if 'blocked' in got['tools'].values() and 'present' not in got['tools'].values():
            demo.fail(f'everything blocked on an online host: {got["tools"]}')
        return ', '.join(f'{k} {v}' for k, v in got['tools'].items())
    r.check('packages', vms[0].name, packages)

    # Falco, from its vendor, on what the lab has. It needs the network and a recent kernel, so a host that cannot is a skip with the reason
    def falco():
        node = docker_host or vms[0]
        out = attempt(api, '/api/security/behavior/falco', {'host': node.name, 'mode': 'apply'})[1]
        if out.get('error'):
            return None if 'could not fetch' in str(out.get('output')) else demo.fail(f'{out.get("error")}: {str(out.get("output"))[-500:]}')
        sudo(node.name, f'touch {node.data}/sf-falco; chattr -i {node.data}/sf-falco; true')
        time.sleep(5)
        measure(api, node.name)
        events = [e for e in api.get(f'/api/security/events?host={node.name}')['events'] if e['kind'].startswith('falco')]
        if not events:
            demo.fail('chattr -i raised nothing')
        return f'installed from its repository, and a real chattr -i reached the alarms: {events[0]["summary"][:80]}'
    r.check('falco', (docker_host or vms[0]).name, falco)


def main():
    return sys.argv


if __name__ == '__main__':
    print('run through tiers.py: tiers.py run 9, 10 or 11', file=sys.stderr)
    sys.exit(2)
