#!/usr/bin/env python3
"""Tier 18 of the KVM lab: managing libvirt (steps_kvm.py and the VM task blocks) on real libvirt, nested in two lab VMs.

    kvm-host        libvirt, qemu and virt-install on two hosts, each scanned, enrolled and measured
    kvm-pool        a folder pool defined, started, moved, and removed with its files left; the default pool made where there is none
    kvm-network     a NAT network with DHCP defined, then changed and restarted; one that a VM uses is refused removal
    kvm-guest       a small Alpine VM from a cloud image, with the guest agent from cloud-init, answering
    kvm-snapshot    a disk-only snapshot with the filesystems frozen (quiesce require: refused unless the agent answers)
    kvm-revert      back to the disk-only snapshot where libvirt can (a file written after it is gone), or refused saying so (10.0 cannot)
    kvm-revert-memory back to an internal snapshot with memory: the file written after it is gone
    kvm-delete      deleting the snapshot merges it back: the VM runs on its own disks again
    kvm-reading     the VM panel's data: the reading lists the VM, its agent, its disks and its snapshots
    kvm-edit        vCPUs, memory, autostart, a disk added and grown, with a restart; then the disk detached and its file kept
    kvm-task-snap   a task snapshotting on each run keeps the newest 2 of its own
    kvm-task-backup a task backing up the running VM: a whole qcow2 and the definition, the VM back on its own disks
    kvm-copy        a VM copied live to the other host through a signed send of each disk, defined there from the reading, booted,
                    its agent answering; the source untouched
    kvm-old-libvirt the same on libvirt 9.0, and a disk-only snapshot deleted there
    kvm-power       force off, then start, as plan steps
    kvm-cleanup     the VMs removed with their definitions (disks kept), the network removed

A check reads the answer from the VM it is about (virsh and the guest agent there), never from StorageForge's report of its
work. The nested guest needs KVM in the lab VMs (nested virtualisation on the workstation) and internet for its packages.
tiers.py runs it.
"""
import json
import shlex
import time

import demo
from demo import STATE

import tiers as t
from tiers_platform import quiet, sudo

GUEST = 'sf-nested'
NET = 'sflab-net'
PKGS = ('DEBIAN_FRONTEND=noninteractive apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends '
        'libvirt-daemon-system libvirt-clients qemu-system-x86 qemu-utils virtinst xorriso dnsmasq-base curl ca-certificates >/dev/null')


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def virsh(vm, *args, check=True):
    return sudo(vm, 'virsh -c qemu:///system ' + shlex.join(args), check=check)


def guest(vm, command, timeout=60):
    """A command in the nested guest, through its agent: what it printed, and its exit status."""
    start = json.dumps({'execute': 'guest-exec', 'arguments': {'path': '/bin/sh', 'arg': ['-c', command], 'capture-output': True}})
    pid = json.loads(virsh(vm, 'qemu-agent-command', GUEST, start))['return']['pid']
    end = time.time() + timeout
    while time.time() < end:
        st = json.loads(virsh(vm, 'qemu-agent-command', GUEST, json.dumps({'execute': 'guest-exec-status', 'arguments': {'pid': pid}})))['return']
        if st.get('exited'):
            import base64
            return base64.b64decode(st.get('out-data') or '').decode(errors='replace'), st.get('exitcode')
        time.sleep(1)
    raise AssertionError(f'{command} did not end in the guest in {timeout} s')


def agent_up(vm, name=GUEST):
    return quiet(vm, f'virsh -c qemu:///system qemu-agent-command {name} \'{{"execute":"guest-ping"}}\' --timeout 5') == 0


def plan(api, name, tasks, destructive=False):
    pid = api.post('/api/changes', {'name': name, 'tasks': tasks})['id']
    runs = demo.deploy(api, 'changes', pid, name, **({'destructive': True} if destructive else {}))
    return pid, runs


def out_of(runs, host):
    return '\n'.join(r.get('output') or '' for r in runs if r['host'] == host)


def tier18(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    names = [n for n in ('sf-ubuntu', 'sf-bookworm') if n in t.VMS]
    if len(names) < 2:
        r.add('kvm-host', '-', None, 'needs sf-ubuntu and sf-bookworm in the build')
        return
    a, b = names
    state = {}

    def host(vm):
        if quiet(vm, 'test -e /dev/kvm') != 0:
            raise AssertionError(f'{vm} has no /dev/kvm: turn on nested virtualisation on the workstation')
        # apt may be held by unattended upgrades just after a reset: try again for a while, then say so
        sudo(vm, f'for i in $(seq 1 20); do command -v virt-install >/dev/null && break; {PKGS} 2>/tmp/sf-apt.err || sleep 30; done; '
                 'command -v virt-install >/dev/null || { tail -n 3 /tmp/sf-apt.err; exit 1; }; systemctl enable --now libvirtd >/dev/null 2>&1 || true')
        api.post('/api/infra/measure', {'host': vm})
        net = next((n for n in api.get(f'/api/workloads/libvirt?host={vm}')['hosts'][0]['networks'] if n['name'] == 'default'), None)
        started = ''
        if net and not net['active']:            # the network step starts one that is there and not running
            bits = sum(bin(int(o)).count('1') for o in net['netmask'].split('.')) if '.' in (net['netmask'] or '') else net['netmask']
            plan(api, f'default network on {vm}', [{'type': 'libvirt-network', 'host': vm, 'params': {
                'name': 'default', 'mode': net['mode'], 'address': f'{net["address"]}/{bits}', 'dhcp': net['dhcp'] or '', 'autostart': True}}])
            want('Active:         yes' in virsh(vm, 'net-info', 'default'), f'the default network on {vm} did not start')
            started = '; its default network started by the network step'
        api.post('/api/infra/measure', {'host': vm})
        version = virsh(vm, 'version', '--daemon')
        return ' '.join(x for x in version.splitlines() if 'daemon' in x).strip() + started
    r.check('kvm-host', a, lambda: host(a))
    r.check('kvm-host', b, lambda: host(b))

    def apply_out(name, tasks):
        """An apply that may be refused: its runs and their output, never raising."""
        pid = api.post('/api/changes', {'name': name, 'tasks': tasks})['id']
        group = api.post('/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'apply', 'destructive': True, 'title': name})['group']
        done = demo.wait(name, lambda: demo.finished(api, group))
        return all(x['status'] == 'ok' for x in done['runs']), '\n'.join(x.get('output') or '' for x in done['runs'])

    # ── pools ───────────────────────────────────────────────────
    def pools():
        for vm in (a, b):
            if quiet(vm, 'virsh -c qemu:///system pool-info default') != 0:
                plan(api, f'default pool on {vm}', [{'type': 'libvirt-pool', 'host': vm, 'params': {'name': 'default', 'type': 'dir', 'path': '/var/lib/libvirt/images', 'autostart': True}}])
            info = virsh(vm, 'pool-info', 'default')
            want('running' in info and 'Autostart:      yes' in info, f'{vm}: default pool: {info}')
        steps = lambda path, **p: [{'type': 'libvirt-pool', 'host': a, 'params': {'name': 'sflab-extra', 'type': 'dir', 'path': path, 'autostart': True, **p}}]   # noqa: E731
        plan(api, 'extra pool', steps('/srv/sflab-vms'))
        want('/srv/sflab-vms<' in virsh(a, 'pool-dumpxml', 'sflab-extra'), 'the pool is not at its folder')
        plan(api, 'extra pool moved', steps('/srv/sflab-vms2'))
        want('/srv/sflab-vms2<' in virsh(a, 'pool-dumpxml', 'sflab-extra') and 'running' in virsh(a, 'pool-info', 'sflab-extra'), 'the pool did not move')
        sudo(a, 'qemu-img create -q -f qcow2 /srv/sflab-vms2/keep-me.qcow2 1M && virsh -c qemu:///system pool-refresh sflab-extra >/dev/null')
        ok, text = apply_out('extra pool moved again', steps('/srv/sflab-vms3'))
        want(not ok and 'holds volumes or files' in text and '/srv/sflab-vms2<' in virsh(a, 'pool-dumpxml', 'sflab-extra'), f'a pool holding a file was moved: {text[-400:]}')
        plan(api, 'extra pool removed', steps('', state='absent'))
        want(quiet(a, 'virsh -c qemu:///system pool-info sflab-extra') != 0, 'the pool is still defined')
        want(quiet(a, 'test -e /srv/sflab-vms2/keep-me.qcow2') == 0, 'removing a pool took a file')
        return 'default pools; one defined, moved while empty, refused a move holding a file, and removed with the file kept'
    r.check('kvm-pool', a, pools)

    # ── networks ────────────────────────────────────────────────
    def networks():
        step = lambda **p: [{'type': 'libvirt-network', 'host': a, 'params': {'name': NET, 'mode': 'nat', 'address': '10.91.0.1/24', 'autostart': True, **p}}]   # noqa: E731
        plan(api, 'lab network', step(dhcp='10.91.0.100-10.91.0.150'))
        x = virsh(a, 'net-dumpxml', NET)
        want("start='10.91.0.100'" in x and 'Active:         yes' in virsh(a, 'net-info', NET), f'the network: {x}')
        _, runs = plan(api, 'lab network changed', step(dhcp='10.91.0.50-10.91.0.60', restart=True))
        x = virsh(a, 'net-dumpxml', NET)
        want("start='10.91.0.50'" in x and "end='10.91.0.60'" in x, f'the change did not apply: {x}')
        _, runs = plan(api, 'lab network again', step(dhcp='10.91.0.50-10.91.0.60', restart=True))
        want('change network' not in out_of(runs, a), 'a second run changed it again')
        return 'defined, changed and restarted, and the same again is no change'
    r.check('kvm-network', a, networks)

    # ── a guest ─────────────────────────────────────────────────
    def make_guest():
        if quiet(a, f'virsh -c qemu:///system dominfo {GUEST}') != 0:
            api.post('/api/infra/measure', {'host': a})
            key = (STATE / 'id_ed25519.pub').read_text().strip()
            plan(api, 'nested guest', [{'type': 'vm-create', 'host': a, 'params': {
                'name': GUEST, 'image': 'alpine324', 'vcpus': '1', 'ram_mb': '256', 'disk_gb': '1', 'pool': 'default', 'network': NET,
                'firmware': 'bios', 'console': 'serial', 'user': 'lab', 'ssh_key': key, 'sudo': 'nopasswd', 'guest_agent': True}}])
        demo.wait('the guest agent', lambda: agent_up(a), timeout=600)
        text, rc = guest(a, 'uname -m; nproc')
        state['vda'] = virsh(a, 'domblklist', GUEST).split('vda')[1].split()[0]
        return f'agent answers; {text.split()[0]}, {text.split()[1]} vCPU, root disk {state["vda"]}'
    r.check('kvm-guest', a, make_guest)

    def snapshot():
        before, _ = guest(a, 'rm -f /root/after; sync; ls /root')
        plan(api, 'snapshot frozen', [{'type': 'vm-snapshot', 'host': a, 'params': {'name': GUEST, 'snapshot': 'lab-1', 'disk_only': True, 'quiesce': 'require'}}])
        x = virsh(a, 'snapshot-dumpxml', GUEST, 'lab-1')
        want('<state>disk-snapshot</state>' in x and "snapshot='external'" in x, f'not a disk-only snapshot: {x[:300]}')
        want('.lab-1' in virsh(a, 'domblklist', GUEST), 'the VM is not on the overlay')
        return 'disk-only, refused unless the agent answered, and it did'
    r.check('kvm-snapshot', a, snapshot)

    def revert_disk_only(vm, snap):
        """Back to a disk-only snapshot: done where libvirt can, else refused with why, and the VM left as it was."""
        ok, text = apply_out(f'revert {vm}', [{'type': 'vm-revert', 'host': vm, 'params': {'name': GUEST, 'snapshot': snap, 'start': True}}])
        version = virsh(vm, 'version', '--daemon').split('daemon:')[1].split()[0]
        if ok:
            demo.wait('the guest agent after the revert', lambda: agent_up(vm), timeout=300)
            got, _ = guest(vm, 'cat /root/after 2>/dev/null || echo gone')
            want('gone' in got, f'the file written after the snapshot is still there: {got}')
            return f'libvirt {version}: back at {snap}, what was written after is gone'
        want('cannot go back to a disk-only snapshot' in text, f'the refusal does not say why: {text[-600:]}')
        want(f'.{snap}' in virsh(vm, 'domblklist', GUEST) and 'running' in virsh(vm, 'domstate', GUEST), 'the VM is not as it was')
        return f'libvirt {version}: refused, saying it cannot go back to a disk-only snapshot, and the VM left running as it was'

    def revert():
        guest(a, 'echo written-after > /root/after; sync')
        return revert_disk_only(a, 'lab-1')
    r.check('kvm-revert', a, revert)

    def delete():
        plan(api, 'delete snapshot', [{'type': 'vm-snapshot', 'host': a, 'params': {'name': GUEST, 'snapshot': 'lab-1', 'action': 'delete'}}])
        want('lab-1' not in virsh(a, 'snapshot-list', GUEST, '--name'), 'the snapshot is still listed')
        disks = virsh(a, 'domblklist', GUEST)
        want(state['vda'] in disks, f'not back on its own disk: {disks}')
        return 'gone, and merged back into its disk'
    r.check('kvm-delete', a, delete)

    def revert_memory():
        guest(a, 'rm -f /root/after; sync')               # the refused revert left it
        plan(api, 'snapshot with memory', [{'type': 'vm-snapshot', 'host': a, 'params': {'name': GUEST, 'snapshot': 'mem-1', 'disk_only': False}}])
        guest(a, 'echo written-after > /root/after; sync')
        plan(api, 'revert with memory', [{'type': 'vm-revert', 'host': a, 'params': {'name': GUEST, 'snapshot': 'mem-1', 'start': True}}], destructive=True)
        want('running' in virsh(a, 'domstate', GUEST), 'it is not running after the revert')
        demo.wait('the guest agent after the revert', lambda: agent_up(a), timeout=300)
        text, _ = guest(a, 'cat /root/after 2>/dev/null || echo gone')
        want('gone' in text, f'the file written after the snapshot is still there: {text}')
        plan(api, 'snapshot with memory gone', [{'type': 'vm-snapshot', 'host': a, 'params': {'name': GUEST, 'snapshot': 'mem-1', 'action': 'delete', 'disk_only': False}}])
        want('mem-1' not in virsh(a, 'snapshot-list', GUEST, '--name'), 'the snapshot is still listed')
        return 'an internal snapshot with memory: back at it, running, what was written after gone; then deleted'
    r.check('kvm-revert-memory', a, revert_memory)

    def reading():
        plan(api, 'snapshot for the panel', [{'type': 'vm-snapshot', 'host': a, 'params': {'name': GUEST, 'snapshot': 'panel', 'disk_only': True}}])
        api.post('/api/infra/measure', {'host': a})
        w = next(x for x in api.get(f'/api/workloads?host={a}')['workloads'] if x['name'] == GUEST)
        want(w['agent'] == 'connected', f'agent: {w["agent"]}')
        want([s['name'] for s in w['snapshots']] == ['panel'] and w['snapshots'][0]['location'] == 'external', f'snapshots: {w["snapshots"]}')
        want(any(d['target'] == 'vda' for d in w['disks']), f'disks: {w["disks"]}')
        lv = api.get(f'/api/workloads/libvirt?host={a}')['hosts'][0]
        want(any(n['name'] == NET and n['active'] for n in lv['networks']) and any(p['name'] == 'default' for p in lv['pools']), f'libvirt: {lv}')
        plan(api, 'snapshot for the panel gone', [{'type': 'vm-snapshot', 'host': a, 'params': {'name': GUEST, 'snapshot': 'panel', 'action': 'delete'}}])
        return 'agent, a disk-only snapshot, disks, the network and the pool, as the panel shows them'
    r.check('kvm-reading', a, reading)

    def edit():
        _, runs = plan(api, 'edit the guest', [{'type': 'vm-edit', 'host': a, 'params': {
            'name': GUEST, 'vcpus': '2', 'memory_mib': '320', 'autostart': 'on', 'add_disk': '256M', 'add_label': 'extra', 'grow_disk': 'vda', 'grow_to': '2G', 'restart': True}}])
        info = virsh(a, 'dominfo', GUEST)
        want('CPU(s):         2' in info and '327680 KiB' in info and 'Autostart:      enable' in info, f'dominfo: {info}')
        want(f'/var/lib/libvirt/images/{GUEST}-extra.qcow2' in virsh(a, 'domblklist', GUEST), 'no new disk')
        cap = int(virsh(a, 'domblkinfo', GUEST, 'vda').split('Capacity:')[1].split()[0])
        want(cap >= 2 * 2**30, f'vda is {cap} bytes')
        demo.wait('the guest agent after the restart', lambda: agent_up(a), timeout=300)
        text, _ = guest(a, 'nproc; ls /sys/block')
        want(text.split()[0] == '2' and 'vdb' in text, f'the guest sees: {text}')
        _, runs = plan(api, 'detach the disk', [{'type': 'vm-edit', 'host': a, 'params': {'name': GUEST, 'remove_disk': 'vdb', 'autostart': 'off'}}])
        want('extra' not in virsh(a, 'domblklist', GUEST) and quiet(a, f'test -f /var/lib/libvirt/images/{GUEST}-extra.qcow2') == 0, 'the disk is attached, or its file went')
        return '2 vCPUs, 320 MiB, autostart, a disk added and vda grown to 2 GiB, seen in the guest; then the disk detached and its file kept'
    r.check('kvm-edit', a, edit)

    def task_snap():
        made = api.post('/api/tasks', {'name': 'Lab VM snapshots', 'host': a, 'blocks': [
            {'type': 'vm_snapshot', 'params': {'vms': GUEST, 'prefix': 'nightly', 'keep': 2, 'quiesce': 'auto'}}]})
        for _ in range(3):
            demo.deploy(api, 'tasks', made['id'], 'VM snapshot task', run=True)
            time.sleep(1.2)        # each run its own second, as a timer would
        left = virsh(a, 'snapshot-list', GUEST, '--name').split()
        want(len(left) == 2 and all(x.startswith('nightly-') for x in left), f'snapshots: {left}')
        for s in left:
            virsh(a, 'snapshot-delete', GUEST, s)
        state['snap_task'] = made['id']
        return f'3 runs, the newest 2 kept: {", ".join(left)}'
    r.check('kvm-task-snap', a, task_snap)

    def task_backup():
        made = api.post('/api/tasks', {'name': 'Lab VM backup', 'host': a, 'blocks': [
            {'type': 'vm_backup', 'params': {'vms': GUEST, 'into': '/srv/sflab-bk', 'keep': 1, 'quiesce': 'auto'}}]})
        demo.deploy(api, 'tasks', made['id'], 'VM backup task', run=True)
        dirs = sudo(a, f'ls /srv/sflab-bk/{GUEST}').split()
        want(len(dirs) == 1, f'backups: {dirs}')
        d = f'/srv/sflab-bk/{GUEST}/{dirs[0]}'
        want(quiet(a, f'qemu-img check {d}/vda.qcow2') == 0 and quiet(a, f'grep -q "<name>{GUEST}</name>" {d}/domain.xml') == 0, 'the backup is not whole')
        want(sudo(a, f'stat -c %a {d}/vda.qcow2').strip() == '600', 'the backup is readable by others')
        want('sfbackup' not in virsh(a, 'domblklist', GUEST) and 'running' in virsh(a, 'domstate', GUEST), 'the VM did not go back to its own disks')
        size = sudo(a, f'du -sh {d}').split()[0]
        return f'{d}: vda.qcow2 checks clean, domain.xml, {size}, mode 600; the VM ran throughout'
    r.check('kvm-task-backup', a, task_backup)

    # ── a copy to the other host ────────────────────────────────
    def copy():
        api.post('/api/infra/measure', {'host': a})
        api.post('/api/infra/measure', {'host': b})
        guest(a, 'echo copied-from-a > /root/marker; sync')
        if quiet(b, 'virsh -c qemu:///system net-info default') != 0:
            raise AssertionError(f'{b} has no default network')
        made = api.post('/api/vm/copy', {'source': a, 'name': GUEST, 'target': b, 'pool': 'default', 'live': True, 'start': True, 'network': 'default'})
        crit = [i['text'] for tk in made['check']['tasks'] for i in tk['items'] if i['level'] == 'crit']
        want(not crit, f'the check: {crit}')
        runs = demo.deploy(api, 'changes', made['id'], 'copy the guest')
        kinds = [(x['host'], x['kind']) for x in runs]
        want((b, 'sends') in kinds, f'no signed receiving run on {b}: {kinds}')
        want('running' in virsh(b, 'domstate', GUEST), f'the copy is not running on {b}')
        want(quiet(b, f'test -f /var/lib/libvirt/images/.{GUEST}-vda.qcow2.sf-sha256') == 0, 'no checksum beside the received disk')
        demo.wait(f'the agent of the copy on {b}', lambda: agent_up(b), timeout=600)
        here = json.loads(virsh(b, 'qemu-agent-command', GUEST, json.dumps({'execute': 'guest-exec', 'arguments': {'path': '/bin/cat', 'arg': ['/root/marker'], 'capture-output': True}})))['return']['pid']
        time.sleep(2)
        import base64
        st = json.loads(virsh(b, 'qemu-agent-command', GUEST, json.dumps({'execute': 'guest-exec-status', 'arguments': {'pid': here}})))['return']
        text = base64.b64decode(st.get('out-data') or '').decode()
        want('copied-from-a' in text, f'the copy holds: {text!r}')
        want('running' in virsh(a, 'domstate', GUEST) and 'sfcopy' not in virsh(a, 'domblklist', GUEST), f'the source is not as it was on {a}')
        macs = [virsh(x, 'domiflist', GUEST).split('virtio')[1].split()[0] for x in (a, b)]
        want(macs[0] != macs[1], f'the copy kept the MAC: {macs}')
        return f'live from {a}, each disk by a signed send and checked; on {b} it boots with the file written just before, its own MAC'
    r.check('kvm-copy', b, copy)

    def old_libvirt():
        plan(api, 'snapshot the copy', [{'type': 'vm-snapshot', 'host': b, 'params': {'name': GUEST, 'snapshot': 'old', 'disk_only': True}}])
        guest(b, 'echo written-after > /root/after; sync')
        note = revert_disk_only(b, 'old')
        plan(api, 'snapshot of the copy gone', [{'type': 'vm-snapshot', 'host': b, 'params': {'name': GUEST, 'snapshot': 'old', 'action': 'delete'}}])
        want('old' not in virsh(b, 'snapshot-list', GUEST, '--name').split(), 'the snapshot is still there')
        return note + '; then deleted on it'
    r.check('kvm-old-libvirt', b, old_libvirt)

    def power():
        plan(api, 'force off', [{'type': 'workload-action', 'host': b, 'params': {'runtime': 'libvirt', 'name': GUEST, 'action': 'force-off'}}])
        want('shut off' in virsh(b, 'domstate', GUEST), 'it is not off')
        plan(api, 'start', [{'type': 'workload-action', 'host': b, 'params': {'runtime': 'libvirt', 'name': GUEST, 'action': 'start'}}])
        want('running' in virsh(b, 'domstate', GUEST), 'it did not start')
        return 'forced off, then started'
    r.check('kvm-power', b, power)

    def cleanup():
        for vm in (a, b):
            plan(api, f'remove the guest on {vm}', [{'type': 'workload-remove', 'host': vm, 'params': {'runtime': 'libvirt', 'name': GUEST}}], destructive=True)
            want(quiet(vm, f'virsh -c qemu:///system dominfo {GUEST}') != 0, f'{GUEST} is still defined on {vm}')
        _, runs = plan(api, 'network gone', [{'type': 'libvirt-network', 'host': a, 'params': {'name': NET, 'state': 'absent'}}])
        want(quiet(a, f'virsh -c qemu:///system net-info {NET}') != 0, 'the network is still there')
        sudo(a, f'rm -rf /srv/sflab-bk /srv/sflab-vms /srv/sflab-vms2 /srv/sflab-vms3 /var/lib/libvirt/images/{GUEST}*')
        sudo(b, f'rm -f /var/lib/libvirt/images/{GUEST}* /var/lib/libvirt/images/.{GUEST}*')
        return 'both guests and the network removed'
    r.check('kvm-cleanup', a, cleanup)
