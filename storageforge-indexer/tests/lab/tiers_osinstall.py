#!/usr/bin/env python3
"""Tier 23 of the KVM lab: a second system beside the first, and a desktop on it (roadmap section 7, phases 8 and 9), on a VM
that was started by UEFI and has a blank disk (`sf-uefi`, which joins a build only by --pick or --join).

NOT RUN. This file was written on 2026-11-20 where the KVM lab cannot run, so no check below has ever passed or failed on a real
VM: it is not lab-tested. What was run is tests/test_osinstall.py, test_osinstall_more.py, test_osoffer.py and
test_desktop_steps.py on this machine, and on 2026-11-18 two VMs by hand through plan scripts (docs/host-migration.md). The lab
had no VM started by UEFI before this tier: lab.sh now asks virt-install for one when nodes.conf says `uefi`, and that line of
lab.sh has only been printed as XML, not started. A first run will most likely have to correct this file before it says
anything about StorageForge. A check that cannot be made shows as skip or as failed, never as passed.

    os-offer          the page's own route offers the blank disk of the scanned host, says the machine was started by UEFI, and
                      lists no second system
    os-install        one form through /api/os-install/plan: an install plan, and a desktop plan of its own. The install plan
                      is reported and applied through the deploy path. Fedora is on the blank disk in partitions named for it,
                      the firmware has one new entry that is not in the boot order, and the running system's disk and its EFI
                      partition are byte for byte what they were. A second run finds it installed
    os-seen           after a scan the route lists the new system, not running
    os-boot-once      a plan with `once` and a restart: the machine comes up as the new system at the same address, with the
                      same SSH host key (the lab's known_hosts is strict), and the boot order was not changed
    os-desktop        in the new system the desktop plan's own script runs: `os-running` goes on, Dux is installed from the
                      pinned release, the profile is written, and `niri validate` accepts the configuration
    os-fallback       a plain restart of the new system is the old one again
    os-guard          in the old system a plan that starts with `os-running` for the new one stops there, and the step after it
                      is not run
    os-broken-start   the new system's loader is moved away, and it is started once with a restart: the machine comes back as
                      the old system by itself. The loader is put back
    os-remove         the partitions and the boot entry are gone, the old system's disk is still what it was, and a second run
                      finds nothing to remove

What a reset to golden does not put back: a VM's UEFI variables are a file of their own, so a boot entry left by a run that was
cut short is still there on the next one. The tier clears entries of its own name before it starts, with efibootmgr, and says so.
"""
import re
import shlex
import subprocess
import time

import demo
import roles

import tiers as t
from tiers_platform import quiet, sudo

NAME = 'uefi-fedora'
IMAGE = 'fedora44'
PROFILE = {'name': 'lab', 'mod': 'super', 'binds': [{'keys': 'mod+Return', 'action': 'spawn', 'arg': 'ghostty'}, {'keys': 'mod+shift+q', 'action': 'close'}],
           'rules': [{'app': 'firefox', 'workspace': '2'}], 'displays': []}
RELEASES = 'https://github.com/duxlabs-dev/dux-shell/releases'
# every file of the running system's EFI partition, as one hash, and the partition table of its disk
ESP_HASH = "cd /boot/efi 2>/dev/null && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1"


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def hostname(node):
    return demo.ssh(node.name, 'hostname', check=False).strip()


def boot_id(node):
    return demo.ssh(node.name, 'cat /proc/sys/kernel/random/boot_id', check=False).strip()


def firmware(node):
    """{'order': '0002,0000', 'next': '' or an entry, 'entries': {number: label}} from efibootmgr."""
    out = sudo(node.name, 'efibootmgr')
    entries = dict(re.findall(r'^Boot([0-9A-Fa-f]{4})\*? ([^\t\n]*?)(?:\t.*)?$', out, re.M))
    return {'order': (re.search(r'^BootOrder: (.*)$', out, re.M) or [None, ''])[1].strip(), 'next': (re.search(r'^BootNext: (.*)$', out, re.M) or [None, ''])[1].strip(),
            'entries': {k: v.strip() for k, v in entries.items()}}


def entry_of(node, name=NAME):
    return next((k for k, v in firmware(node)['entries'].items() if v == f'sf-{name}'), None)


def parts_of(node, name=NAME):
    out = sudo(node.name, 'lsblk -rno PATH,PARTLABEL,FSTYPE')
    return [line.split() for line in out.splitlines() if len(line.split()) >= 2 and line.split()[1].startswith(f'sf-{name}-')]


def root_disk(node):
    return sudo(node.name, 'lsblk -no PKNAME "$(findmnt -no SOURCE / | sed "s/\\[.*//")" | head -n 1').strip()


def old_system(node):
    """What must not change: the partition table of the disk the running system is on, and its EFI partition."""
    disk = root_disk(node)
    return sudo(node.name, f'sfdisk -d /dev/{disk}').strip(), sudo(node.name, ESP_HASH).strip()


def comes_up_as(node, name, before, what, timeout=600):
    """The machine has been restarted (its boot id is another one) and calls itself `name`."""
    def up():
        now = boot_id(node)
        return now and now != before and hostname(node) == name
    t.wait_for(what, up, timeout)


def staged(api, body):
    made = api.post('/api/os-install/plan', body)
    want(made.get('plans'), f'no plan was saved: {made}')
    return made['plans']


def said(runs):
    return '\n'.join(x.get('output') or '' for x in runs or [])


def newest_dux():
    """The newest Dux release and the hash its project publishes for that release's installer: what a person reads off the
    release page before filling in the step. None where it cannot be read from here."""
    try:
        head = subprocess.run(['curl', '-sI', '--max-time', '30', f'{RELEASES}/latest'], capture_output=True, text=True, timeout=60).stdout
        tag = re.search(r'(?im)^location:.*/releases/tag/(v[0-9]+(?:\.[0-9]+){1,3})\s*$', head)
        if not tag:
            return None
        got = subprocess.run(['curl', '-fsSL', '--max-time', '60', f'{RELEASES}/download/{tag[1]}/duxinstall-amd64.gz.sha256'], capture_output=True, text=True, timeout=90).stdout.split()
        return (tag[1], got[0]) if got and re.fullmatch(r'[0-9a-f]{64}', got[0]) else None
    except (OSError, subprocess.SubprocessError):
        return None


def tier23(r):
    nodes = roles.extra('uefi')
    if not nodes:
        r.add('os-install', '-', None, 'no VM started by UEFI in this build: up --join sf-uefi')
        return
    node = nodes[0]
    api = demo.sign_in()
    demo.scan_everything(api)
    # sf-uefi is in no other tier's build, so the keys, the binding, the first scan and deploy access are set up here, as demo.py does for the rest
    keys = {k['name']: k['public_key'] for k in api.get('/api/keys')['keys']}
    demo.install_key(node.name, 'scan', keys['lab-scan'])
    demo.install_key(node.name, 'sfadmin', keys['lab-admin'])
    demo.cli('vault', 'bind', '--key', 'lab-scan', '--host', node.ip, '--user', 'scan', '--actions', 'scan,checksum')
    demo.scan(api, [node.ip])
    api.post('/api/hostkey/confirm', {'host': node.ip, 'fingerprint': demo.ssh(node.name, 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub').split()[1]})
    host = next((h['hostname'] for h in api.get('/api/hosts')['indexed'] if h['ip'] == node.ip or h['hostname'] == node.name), node.name)
    access = api.post('/api/deploy/access', {'host': host, 'admin_user': 'sfadmin', 'admin_key': 'lab-admin', 'password': (demo.STATE / 'admin-password').read_text().strip()})
    if access['state'] != 'ready':
        r.add('os-install', node.name, False, f'deploy access is {access["state"]}', access.get('output', ''))
        return
    if quiet(node.name, 'test -d /sys/firmware/efi'):
        r.add('os-install', node.name, False, 'the VM was not started by UEFI: the libvirt host has no OVMF, or lab.sh did not ask for it')
        return
    stale = [k for k, v in firmware(node)['entries'].items() if v.startswith('sf-')]
    for k in stale:          # left by a run that was cut short: a reset to golden does not put the UEFI variables back
        sudo(node.name, f'efibootmgr -q -b {k} -B')
    if stale:
        demo.say(f'  {node.name}: cleared {len(stale)} boot entr{"y" if len(stale) == 1 else "ies"} of an earlier run')
    key = (demo.STATE / 'id_ed25519.pub').read_text().strip()
    host_key = demo.ssh(node.name, 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub').split()[1]
    before = old_system(node)
    order = firmware(node)['order']
    state = {}

    def offer():
        mine = next(h for h in api.get('/api/os-install/offer')['hosts'] if h['host'] == host)
        want(mine['started_by'] == 'uefi', f'the route says the machine was started by {mine["started_by"]}')
        want(not mine['systems'], f'second systems before any was installed: {mine["systems"]}')
        blank = [d for d in mine['disks'] if d['blank'] and d['usable']]
        want(len(blank) == 1, f'one blank disk was expected: {mine["disks"]}')
        want(blank[0]['size'] >= 20 * 1024 ** 3, f'the blank disk is {blank[0]["size"]} bytes')
        running = next((d for d in mine['disks'] if d['running']), None)
        want(running and running['path'] != blank[0]['path'], 'the disk the system runs from is not told apart from the blank one')
        state['disk'] = blank[0]['path']
        return f'{blank[0]["path"]} is offered as a blank disk, and the machine as started by UEFI'
    r.check('os-offer', node.name, offer)
    if 'disk' not in state:
        r.add('os-install', node.name, None, 'no disk was offered')
        return

    def install():
        api('PUT', '/api/desktop/profiles/lab', PROFILE)
        dux = newest_dux()
        desk = {'profile': 'lab', 'profile_compositor': 'niri'} | ({'dux': True, 'compositor': 'niri', 'terminal': 'ghostty', 'version': dux[0], 'installer_sha': dux[1]} if dux else {})
        plans = staged(api, {'kind': 'install', 'host': host, 'name': NAME, 'image': IMAGE, 'disk': state['disk'], 'confirm': state['disk'], 'size_gb': '10',
                             'user': 'lab', 'ssh_key': key, 'network': 'fixed', 'start': 'no', 'desktop': desk})
        want([p['tasks'] for p in plans] == [1, 3 if dux else 2], f'an install plan and a desktop plan were expected: {plans}')
        state.update(install=plans[0]['plan_id'], desktop=plans[1]['plan_id'], dux=dux)
        runs = demo.deploy(api, 'changes', plans[0]['plan_id'], f'install {NAME} on {node.name}', destructive=True)
        made = parts_of(node)
        want(made and any(p[1] == f'sf-{NAME}-root' for p in made), f'no partitions named for {NAME}: {made}')
        want(all(p[0].startswith(state['disk']) for p in made), f'partitions outside {state["disk"]}: {made}')
        entry = entry_of(node)
        fw = firmware(node)
        want(entry, f'the firmware has no entry sf-{NAME}: {fw["entries"]}')
        want(fw['order'] == order and entry.lower() not in fw['order'].lower().split(','), f'the boot order was {order} and is {fw["order"]}')
        want(not fw['next'], f'a one-time start was set by the install: {fw["next"]}')
        want(old_system(node) == before, 'the disk or the EFI partition of the running system changed')
        again = demo.deploy(api, 'changes', plans[0]['plan_id'], f'install {NAME} on {node.name} again', destructive=True)
        want(f'{NAME} is installed' in said(again), f'a second run did not find it installed:\n{said(again)[-600:]}')
        note = re.search(r'Secure Boot[^\n]*', said(runs))
        return f'{len(made)} partitions on {state["disk"]}, entry {entry} outside the boot order {order}; the old disk and EFI partition unchanged; {note[0][:80] if note else "nothing said of Secure Boot"}'
    r.check('os-install', node.name, install)
    if not entry_of(node):
        for check in ('os-seen', 'os-boot-once', 'os-desktop', 'os-fallback', 'os-guard', 'os-broken-start', 'os-remove'):
            r.add(check, node.name, None, 'nothing was installed')
        return

    def seen():
        demo.scan(api, [node.ip])
        mine = next(h for h in api.get('/api/os-install/offer')['hosts'] if h['host'] == host)
        want([(s['name'], s['running'], s['disk']) for s in mine['systems']] == [(NAME, False, state['disk'])], f'the route lists {mine["systems"]}')
        return f'{NAME} on {state["disk"]}, not running'
    r.check('os-seen', node.name, seen)

    def once():
        boot = boot_id(node)
        plan = staged(api, {'kind': 'boot', 'host': host, 'name': NAME, 'when': 'once', 'restart': 'yes'})[0]
        demo.deploy(api, 'changes', plan['plan_id'], f'start {NAME} once')
        comes_up_as(node, NAME, boot, f'{node.name} to come up as {NAME}')
        want('ID=fedora' in demo.ssh(node.name, 'cat /etc/os-release'), 'it is not Fedora that came up')
        want(node.ip in demo.ssh(node.name, 'ip -4 -o addr show scope global'), f'the new system is not at {node.ip}')
        want(demo.ssh(node.name, 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub').split()[1] == host_key, 'the new system has another SSH host key')
        want(quiet(node.name, 'true') == 0, 'the login account has no sudo')
        fw = firmware(node)
        want(fw['order'] == order and not fw['next'], f'after the one-time start the order is {fw["order"]} and the next start {fw["next"] or "nothing"}')
        root = sudo(node.name, 'lsblk -no PARTLABEL "$(findmnt -no SOURCE / | sed "s/\\[.*//")"').strip()
        want(root == f'sf-{NAME}-root', f'its root is on {root}')
        return f'Fedora at {node.ip} with the same host key, its root on sf-{NAME}-root; the boot order is still {order}'
    r.check('os-boot-once', node.name, once)
    in_new = hostname(node) == NAME

    def desktop():
        script = api.text(f'/api/changes/{state["desktop"]}/script')
        want(f'run 1 {NAME} os-running' in script, 'the desktop plan is not for the new system by its own host name')
        out = demo.ssh(node.name, 'cat >/tmp/sf-desktop.sh && sudo -n bash /tmp/sf-desktop.sh --apply 2>&1; echo "exit=$?"', stdin=script, check=False)
        want(f'{NAME} is the system that is running' in out, f'os-running did not go on:\n{out[-800:]}')
        if not state['dux']:
            want('has no' in out and 'config.kdl' in out, f'with no compositor installed the profile step should wait for one:\n{out[-800:]}')
            return 'the newest Dux release could not be read from here, so Dux was not installed: os-running went on, and the profile waits for a compositor'
        want('exit=0' in out, f'the desktop plan failed:\n{out[-1500:]}')
        want(f'Dux {state["dux"][0]} is installed for lab' in out or 'Dux is installed' in out, f'Dux was not installed:\n{out[-1500:]}')
        want('lab has the profile lab for niri' in out, f'the profile was not written:\n{out[-800:]}')
        want('ghostty' in sudo(node.name, 'cat /home/lab/.config/niri/storageforge.kdl'), 'the file on the host is not the profile')
        want(quiet(node.name, 'runuser -u lab -- niri validate -c /home/lab/.config/niri/config.kdl') == 0, 'niri refuses the configuration with the profile in it')
        again = demo.ssh(node.name, 'sudo -n bash /tmp/sf-desktop.sh --apply 2>&1', check=False)
        want('Dux is installed' in again and 'lab has the profile lab for niri' in again, f'a second run did not find it in place:\n{again[-800:]}')
        return f'Dux {state["dux"][0]} with niri, the profile written, niri validate accepts it; a second run changed nothing. No graphical session was started'
    if in_new:
        r.check('os-desktop', node.name, desktop)
    else:
        r.add('os-desktop', node.name, None, 'the new system did not come up')

    def fallback():
        boot = boot_id(node)
        sudo(node.name, 'systemctl reboot', check=False)
        comes_up_as(node, node.name, boot, f'{node.name} to come back as itself')
        want(old_system(node) == before, 'the disk or the EFI partition of the old system is not what it was')
        return 'a plain restart of the new system is the old one again, as it was'
    if in_new:
        r.check('os-fallback', node.name, fallback)
    else:
        r.add('os-fallback', node.name, None, 'the new system did not come up')
    if hostname(node) != node.name:
        for check in ('os-guard', 'os-broken-start', 'os-remove'):
            r.add(check, node.name, None, 'the old system is not the one running')
        return

    def guard():
        plan = api.post('/api/changes', {'name': f'lab: only in {NAME}', 'tasks': [
            {'type': 'os-running', 'host': host, 'params': {'name': NAME}}, {'type': 'os-boot', 'host': host, 'params': {'name': NAME, 'when': 'once'}}]})          # harmless if it did run: the tier clears it
        out = demo.ssh(node.name, 'cat >/tmp/sf-guard.sh && sudo -n bash /tmp/sf-guard.sh --apply 2>&1; echo "exit=$?"', stdin=api.text(f'/api/changes/{plan["id"]}/script'), check=False)
        api('DELETE', f'/api/changes/{plan["id"]}')
        want(f'{NAME} is installed and is not the system that is running' in out, f'os-running did not stop the plan:\n{out[-800:]}')
        want('skipped: an earlier task failed' in out and 'exit=0' not in out, f'the step after it was not skipped:\n{out[-800:]}')
        fw = firmware(node)
        if fw['next']:
            sudo(node.name, 'efibootmgr -q -N', check=False)
        want(not fw['next'] and fw['order'] == order, f'the step after os-running ran: the next start was {fw["next"] or "nothing"} and the order {fw["order"]}')
        return 'the plan stopped at os-running, and the step after it set nothing'
    r.check('os-guard', node.name, guard)

    def broken():
        esp = next((p[0] for p in parts_of(node) if len(p) > 2 and p[2] == 'vfat'), None)
        want(esp, f'the EFI partition of {NAME} was not found: {parts_of(node)}')
        q = shlex.quote(esp)
        sudo(node.name, f'mkdir -p /mnt/sf-lab-esp && mount {q} /mnt/sf-lab-esp && mv /mnt/sf-lab-esp/EFI /mnt/sf-lab-esp/EFI.lab-off && umount /mnt/sf-lab-esp')
        try:
            boot = boot_id(node)
            plan = staged(api, {'kind': 'boot', 'host': host, 'name': NAME, 'when': 'once', 'restart': 'yes'})[0]
            demo.deploy(api, 'changes', plan['plan_id'], f'start {NAME} once, with its loader gone')
            comes_up_as(node, node.name, boot, f'{node.name} to come back after a start that cannot work', 900)
            want(not firmware(node)['next'], 'the one-time start is still set')
        finally:
            t.wait_for(f'{node.name} to answer', lambda: quiet(node.name, 'true') == 0, 600)
            sudo(node.name, f'mount {q} /mnt/sf-lab-esp && mv /mnt/sf-lab-esp/EFI.lab-off /mnt/sf-lab-esp/EFI; umount /mnt/sf-lab-esp', check=False)
        return 'with its loader gone the new system was tried once, and the machine came back as the old one by itself'
    r.check('os-broken-start', node.name, broken)

    def remove():
        plan = staged(api, {'kind': 'remove', 'host': host, 'name': NAME})[0]
        demo.deploy(api, 'changes', plan['plan_id'], f'remove {NAME}', destructive=True)
        want(not parts_of(node), f'partitions of {NAME} are still there: {parts_of(node)}')
        want(not entry_of(node), 'its boot entry is still there')
        want(old_system(node) == before, 'the disk or the EFI partition of the old system changed')
        again = demo.deploy(api, 'changes', plan['plan_id'], f'remove {NAME} again', destructive=True)
        want(f'there is no system named {NAME} here' in said(again), f'a second run did not find it gone:\n{said(again)[-600:]}')
        time.sleep(2)
        demo.scan(api, [node.ip])
        mine = next(h for h in api.get('/api/os-install/offer')['hosts'] if h['host'] == host)
        want(not mine['systems'], f'the route still lists {mine["systems"]}')
        return 'its partitions and its boot entry are gone, the old system is what it was, and a second run found nothing to remove'
    r.check('os-remove', node.name, remove)
