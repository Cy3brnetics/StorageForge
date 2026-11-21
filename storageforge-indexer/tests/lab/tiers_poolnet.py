#!/usr/bin/env python3
"""Tier 26 of the KVM lab: the pool and network steps of the change engine (roadmap section 5, 0.5.9), and the network part of the
section's exit test: a bridge change that cuts SSH rolls itself back.

NOT RUN. This file was written on 2026-11-20 where the KVM lab cannot run, so no check below has ever passed or failed on a real VM:
it is not lab-tested. What was run is tests/test_pool_steps.py, test_network_steps.py and test_netconfig.py on this machine: the
scripts against stand-in zpool, mdadm, ip, netplan, nmcli, networkctl and ifup, and the real cryptsetup on an image file. A first run
will most likely have to correct this file before it says anything about StorageForge. A check that cannot be made shows as skip or as
failed, never as passed.

The pool checks run on `sf-pools` (Ubuntu 24.04, six blank 2 GB disks, and two NICs on the lab's isolated segments that nothing sets
up), which joins a build only with `lab.sh up --join sf-pools` and is in no other tier's build. Ubuntu has ZFS in its kernel and keeps
its network with netplan. The network checks run there too, and on one host of the build for each other system it finds keeping the
network (NetworkManager on the Enterprise Linux and Fedora hosts, systemd-networkd or ifupdown where a cloud image has them), asking
each host which one it has rather than assuming.

    zfs-add             a mirror pool takes a second mirror of two disks
    zfs-add-refused     a single disk is not added to the mirror pool: the check says so, the apply stops with a conflict, nothing
                        is forced and the pool keeps its two vdevs
    zfs-replace         a disk is replaced, the resilver is watched to its end, and the old disk is out of the pool
    zfs-attach          a third side for a mirror
    md-add              a spare for a raid1 made by md-array
    md-grow             the raid1 grown onto the spare, to three devices, and the resync watched to its end
    md-replace          a disk replaced with mdadm --replace, and a second run of the plan takes the old one out
    luks-format         a disk formatted as LUKS2 and opened, with the key from the vault: on stdin, never on a command line, in the
                        plan, the script or the output, and the key file gone after
    luks-add-key        a second key: each of the two opens it
    luks-close-open     closed, then opened with the second key
    net-bond            a bond over the two NICs nothing set up, with an address, kept across a reboot
    net-config-read     a scan reads the netplan files: the map and /api/network show the bond as configured, with its members
    net-address-<sys>   an address given and taken away again, on each system that keeps a network
    net-route-<sys>     a route added and removed again
    net-dhcp            DHCP on for the primary NIC of sf-pools under a rollback timer: still reachable, and the second signed run
                        stops the timer
    bridge-cut-<sys>    the exit test: the interface StorageForge comes in on moved into a bridge with no address, under a timer of
                        one minute. SSH is cut, nothing can confirm it, and the timer puts it back
"""
import json
import shlex
import time

import demo
import roles

import tiers as t
from tiers_platform import connects, plan, quiet, sudo

SECRETS = {'sflab-luks-1': 'lab first luks key 2026', 'sflab-luks-2': 'lab second luks key 2026'}
FREE_NET = '10.99.26'           # addresses no lab network uses
ROUTE_TO = '10.97.0.0/16'


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def disks(node):
    """The six data disks, by the serial lab.sh gave each: {1: '/dev/vdb', ...}."""
    out = sudo(node.name, 'for d in /sys/block/vd*; do echo "${d##*/} $(cat $d/serial 2>/dev/null)"; done')
    return {int(s.removeprefix('sflab-data')): f'/dev/{n}' for n, s in (line.split() for line in out.splitlines() if len(line.split()) == 2) if s.startswith('sflab-data')}


def primary(node):
    return sudo(node.name, "ip -o route get 10.77.0.1 | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p'").strip()


def backend(node):
    """Which system keeps the network, as the steps work it out."""
    test = ('if command -v netplan >/dev/null && ls /etc/netplan/*.yaml >/dev/null 2>&1; then echo netplan; '
            'elif [ "$(nmcli -t -f RUNNING general 2>/dev/null)" = running ]; then echo nm; '
            'elif systemctl is-active -q systemd-networkd; then echo networkd; '
            'elif [ -r /etc/network/interfaces ] && command -v ifup >/dev/null; then echo ifupdown; else echo none; fi')
    return sudo(node.name, test).strip()


def destructive(api, title, *tasks, may_fail=None):
    pid = api.post('/api/changes', {'name': title, 'tasks': [{'type': k, 'host': h, 'params': p} for k, h, p in tasks]})['id']
    return pid, demo.deploy(api, 'changes', pid, title, destructive=True, may_fail=may_fail)


def said(runs):
    return '\n'.join(x.get('output') or '' for x in runs or [])


def checked(api, task):
    got = api.post('/api/changes/check', {'name': 'look', 'tasks': [task]})
    return [(i['level'], i['text']) for x in got['tasks'] for i in x['items']]


def zpool(node):
    return sudo(node.name, 'zpool status -P sfpool 2>&1; true')


def md(node):
    return sudo(node.name, 'mdadm --detail /dev/md/sfmd 2>&1; true')


def wait_quiet(node, what, test, seconds=600):
    t.wait_for(what, lambda: quiet(node.name, test) == 0, seconds)


def setup(api, node):
    """sf-pools is in no other tier's build: its keys, the binding, a first scan and deploy access, as tier 23 does for sf-uefi."""
    keys = {k['name']: k['public_key'] for k in api.get('/api/keys')['keys']}
    demo.install_key(node.name, 'scan', keys['lab-scan'])
    demo.install_key(node.name, 'sfadmin', keys['lab-admin'])
    demo.cli('vault', 'bind', '--key', 'lab-scan', '--host', node.ip, '--user', 'scan', '--actions', 'scan,checksum')
    demo.scan(api, [node.ip])
    api.post('/api/hostkey/confirm', {'host': node.ip, 'fingerprint': demo.ssh(node.name, 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub').split()[1]})
    host = next((h['hostname'] for h in api.get('/api/hosts')['indexed'] if h['ip'] == node.ip or h['hostname'] == node.name), node.name)
    access = api.post('/api/deploy/access', {'host': host, 'admin_user': 'sfadmin', 'admin_key': 'lab-admin', 'password': (demo.STATE / 'admin-password').read_text().strip()})
    return host, access


def send_secret(node, name):
    """The secret into the vault, and to the host as vault send-secret writes it: on stdin, into memory, mode 600."""
    demo.ssh('sf-ctl', f'{demo.COMPOSE} exec -T storageforge storageforge-index vault secret-add {name}', stdin=SECRETS[name] + '\n', check=False)
    sudo(node.name, f'umask 077; mkdir -p /run/storageforge/secrets && chmod 700 /run/storageforge/secrets && cat >/run/storageforge/secrets/{name}', stdin=SECRETS[name] + '\n')


def opens(node, dev, name):
    return quiet(node.name, f'printf %s {shlex.quote(SECRETS[name])} | cryptsetup open --test-passphrase --key-file=- {dev}') == 0


def pools(r, api, node, host, d):
    def zfs_add():
        destructive(api, 'pool for tier 26', ('zfs-pool', host, {'pool': 'sfpool', 'level': 'mirror', 'devices': f'{d[1]} {d[2]}', 'confirm': f'{d[1]} {d[2]}', 'wipe': True}))
        demo.scan(api, [node.ip])
        devs = f'{d[3]} {d[4]}'
        _, runs = destructive(api, 'zfs-add', ('zfs-add', host, {'pool': 'sfpool', 'level': 'mirror', 'devices': devs, 'confirm': devs, 'wipe': True}))
        st = zpool(node)
        want('mirror-1' in st and d[3] in st and d[4] in st, f'no second mirror: {st}')
        _, again = destructive(api, 'zfs-add again', ('zfs-add', host, {'pool': 'sfpool', 'level': 'mirror', 'devices': devs, 'confirm': devs, 'wipe': True}))
        want('already in pool sfpool' in said(again), f'a second run did not find it done: {said(again)[-400:]}')
        return 'two mirrors of two, and a second run finds it done'
    r.check('zfs-add', node.name, zfs_add)

    def zfs_add_refused():
        demo.scan(api, [node.ip])
        task = {'type': 'zfs-add', 'host': host, 'params': {'pool': 'sfpool', 'level': 'stripe', 'devices': d[5], 'confirm': d[5], 'wipe': True}}
        crit = [x for lv, x in checked(api, task) if lv == 'crit']
        want(any('mismatched layout' in x for x in crit), f'the check did not flag it: {crit}')
        # the report already stops at the conflict (the script exits 1 on one), so nothing is left to apply
        pid = api.post('/api/changes', {'name': 'zfs-add a single disk', 'tasks': [task]})['id']
        group = api.post('/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'report', 'title': 'zfs-add a single disk (report)'})['group']
        out = demo.wait('the report', lambda: demo.finished(api, group))
        want(out['runs'] and out['runs'][0]['status'] != 'ok', f'the report ended {out["runs"]}: it should have stopped at the conflict')
        want('never forces it' in said(out['runs']), f'the host did not say why: {said(out["runs"])[-400:]}')
        st = zpool(node)
        want(d[5] not in st and 'mirror-2' not in st, f'the disk went in: {st}')
        want(quiet(node.name, 'grep -rqs "zpool add.* -f" /var/log/storageforge') != 0, 'a forced zpool add is in the log')
        return 'flagged by the check, stopped on the host, and the pool still has its two mirrors'
    r.check('zfs-add-refused', node.name, zfs_add_refused)

    def zfs_replace():
        destructive(api, 'zfs-replace', ('zfs-replace', host, {'pool': 'sfpool', 'old': d[4], 'device': d[5], 'confirm': d[5], 'wipe': True}))
        wait_quiet(node, 'the resilver to end', "! zpool status sfpool | grep -q 'resilver in progress'", 600)
        st = zpool(node)
        want(d[5] in st and d[4] not in st, f'the disks are not as replaced: {st}')
        return f'{d[5]} took the place of {d[4]}, and the resilver ended'
    r.check('zfs-replace', node.name, zfs_replace)

    def zfs_attach():
        demo.scan(api, [node.ip])
        destructive(api, 'zfs-attach', ('zfs-attach', host, {'pool': 'sfpool', 'existing': d[1], 'device': d[4], 'confirm': d[4], 'wipe': True}))
        wait_quiet(node, 'the resilver to end', "! zpool status sfpool | grep -q 'resilver in progress'", 600)
        st = zpool(node).split('mirror-1')[0]
        want(st.count('/dev/vd') == 3, f'mirror-0 does not have three sides: {st}')
        return 'mirror-0 has three sides'
    r.check('zfs-attach', node.name, zfs_attach)
    sudo(node.name, 'zpool destroy -f sfpool 2>/dev/null; for n in 1 2 3 4 5 6; do d=$(for x in /sys/block/vd*; do [ "$(cat $x/serial 2>/dev/null)" = sflab-data$n ] && echo /dev/${x##*/}; done); '
                    'zpool labelclear -f "$d" 2>/dev/null; wipefs -aq "$d"; done; true', check=False)

    def md_add():
        demo.scan(api, [node.ip])
        devs = f'{d[1]} {d[2]}'
        destructive(api, 'md for tier 26', ('md-array', host, {'name': 'sfmd', 'level': 'raid1', 'devices': devs, 'confirm': devs, 'wipe': True}))
        wait_quiet(node, 'the first sync', "! grep -q resync /proc/mdstat", 600)
        destructive(api, 'md-add', ('md-add', host, {'name': 'sfmd', 'device': d[3], 'confirm': d[3], 'wipe': True}))
        detail = md(node)
        want(f'spare   {d[3]}' in ' '.join(detail.split('\n')) or ('spare' in detail and d[3] in detail), f'{d[3]} is not a spare: {detail}')
        return f'{d[3]} is a spare of sfmd'
    r.check('md-add', node.name, md_add)

    def md_grow():
        _, runs = destructive(api, 'md-grow', ('md-grow', host, {'name': 'sfmd', 'devices': d[3], 'confirm': d[3]}))
        want('growing to 3 devices' in said(runs), f'the run does not say it grows: {said(runs)[-400:]}')
        wait_quiet(node, 'the resync to end', "! grep -Eq 'resync|recovery|reshape' /proc/mdstat", 900)
        detail = md(node)
        want('Raid Devices : 3' in detail, f'not three devices: {detail}')
        _, again = destructive(api, 'md-grow again', ('md-grow', host, {'name': 'sfmd', 'devices': d[3], 'confirm': d[3]}))
        want('are in sfmd' in said(again), f'a second run did not find it done: {said(again)[-400:]}')
        return 'three active devices after the resync, and a second run finds it done'
    r.check('md-grow', node.name, md_grow)

    def md_replace():
        params = {'name': 'sfmd', 'old': d[2], 'device': d[4], 'confirm': d[4], 'wipe': True}
        destructive(api, 'md-replace', ('md-replace', host, params))
        wait_quiet(node, 'the copy to end', "! grep -Eq 'recovery|resync' /proc/mdstat", 900)
        destructive(api, 'md-replace again', ('md-replace', host, params))
        detail = md(node)
        want(d[4] in detail and d[2] not in detail, f'the old disk is still listed, or the new one is not: {detail}')
        return f'{d[4]} copied while the array stayed redundant, and the second run took {d[2]} out'
    r.check('md-replace', node.name, md_replace)
    sudo(node.name, 'mdadm --stop /dev/md/sfmd 2>/dev/null; for x in /sys/block/vd*; do case $(cat $x/serial 2>/dev/null) in sflab-data*) mdadm --zero-superblock /dev/${x##*/} 2>/dev/null; wipefs -aq /dev/${x##*/};; esac; done; '
                    'sed -i "/sfmd/d" /etc/mdadm/mdadm.conf 2>/dev/null; true', check=False)

    dev = d[6]

    def luks_format():
        send_secret(node, 'sflab-luks-1')
        params = {'device': dev, 'name': 'sflab-crypt', 'secret': 'sflab-luks-1', 'open': True, 'crypttab': 'noauto', 'confirm': dev, 'wipe': True}
        pid, runs = destructive(api, 'luks-format', ('luks-format', host, params))
        want(quiet(node.name, f'cryptsetup isLuks {dev} && test -e /dev/mapper/sflab-crypt') == 0, 'not LUKS, or not open')
        want(quiet(node.name, 'test ! -e /run/storageforge/secrets/sflab-luks-1') == 0, 'the key file is still there')
        want(quiet(node.name, 'grep -q "^sflab-crypt UUID=.* none luks,noauto$" /etc/crypttab') == 0, 'no crypttab line')
        key = SECRETS['sflab-luks-1']
        script = api.text(f'/api/changes/{pid}/script')
        want(key not in said(runs) and key not in script and key not in json.dumps(api.get(f'/api/changes/{pid}')), 'the key is in the plan, the script or the output')
        want(quiet(node.name, f'grep -rqsF {shlex.quote(key)} /var/log/storageforge') != 0, 'the key is in a log on the host')
        return 'LUKS2, open, listed in crypttab, and the key in no plan, script, output or log'
    r.check('luks-format', node.name, luks_format)

    def luks_add_key():
        send_secret(node, 'sflab-luks-1')
        send_secret(node, 'sflab-luks-2')
        plan(api, 'luks-add-key', [{'type': 'luks-add-key', 'host': host, 'params': {'device': dev, 'secret': 'sflab-luks-1', 'new_secret': 'sflab-luks-2'}}])
        want(opens(node, dev, 'sflab-luks-1') and opens(node, dev, 'sflab-luks-2'), 'one of the two keys does not open it')
        want(quiet(node.name, 'ls -A /run/storageforge/secrets | grep -q .') != 0, 'a key file, or the temporary one, is left in /run/storageforge/secrets')
        return 'each of the two keys opens it, and no key file is left'
    r.check('luks-add-key', node.name, luks_add_key)

    def luks_close_open():
        plan(api, 'luks-close', [{'type': 'luks-close', 'host': host, 'params': {'name': 'sflab-crypt'}}])
        want(quiet(node.name, 'test ! -e /dev/mapper/sflab-crypt') == 0, 'still open')
        send_secret(node, 'sflab-luks-2')
        plan(api, 'luks-open', [{'type': 'luks-open', 'host': host, 'params': {'device': dev, 'name': 'sflab-crypt', 'secret': 'sflab-luks-2'}}])
        want(quiet(node.name, 'test -e /dev/mapper/sflab-crypt') == 0, 'not open with the second key')
        return 'closed, and opened again with the second key'
    r.check('luks-close-open', node.name, luks_close_open)
    sudo(node.name, 'cryptsetup close sflab-crypt 2>/dev/null; sed -i "/^sflab-crypt /d" /etc/crypttab; true', check=False)


def address_and_route(r, api, node, host, kind, n):
    nic = primary(node)
    addr = f'{FREE_NET}.{n}/24'

    def address():
        plan(api, f'address on {node.name}', [{'type': 'net-address', 'host': host, 'params': {'iface': nic, 'address': addr}}])
        want(quiet(node.name, f'ip -o addr show dev {nic} | grep -qF " {addr} "') == 0, f'{nic} does not have {addr}')
        _, again = plan(api, f'address on {node.name} again', [{'type': 'net-address', 'host': host, 'params': {'iface': nic, 'address': addr}}])
        want('keeps it' in said(again), f'a second run did not find it kept: {said(again)[-400:]}')
        plan(api, f'address off {node.name}', [{'type': 'net-address', 'host': host, 'params': {'iface': nic, 'address': addr, 'state': 'absent'}}])
        want(quiet(node.name, f'ip -o addr show dev {nic} | grep -qF " {addr} "') != 0, f'{addr} is still on {nic}')
        return f'{addr} given to {nic} with {kind}, found kept by a second run, and taken off'
    r.check(f'net-address-{kind}', node.name, address)

    def route():
        gw = sudo(node.name, "ip -o route show default | sed -n 's/.* via \\([^ ]*\\).*/\\1/p' | head -n 1").strip()
        want(gw, 'no default gateway to route through')
        plan(api, f'route on {node.name}', [{'type': 'net-route', 'host': host, 'params': {'dst': ROUTE_TO, 'via': gw, 'metric': '77'}}])
        want(quiet(node.name, f'ip -o route show to exact {ROUTE_TO} | grep -q "via {gw}"') == 0, 'the route is not there')
        plan(api, f'route off {node.name}', [{'type': 'net-route', 'host': host, 'params': {'dst': ROUTE_TO, 'via': gw, 'metric': '77', 'state': 'absent'}}])
        want(quiet(node.name, f'ip -o route show to exact {ROUTE_TO} | grep -q .') != 0, 'the route is still there')
        return f'{ROUTE_TO} via {gw} with {kind}, and gone again'
    r.check(f'net-route-{kind}', node.name, route)


def bridge_cut(r, api, node, host, kind):
    """The exit test: as tier 10's bridge-rollback, on each system that keeps a network."""
    def run():
        nic = primary(node)
        task = {'type': 'net-bridge', 'host': host, 'params': {'name': 'sfbrcut', 'ports': nic}}
        got = api.post('/api/map/whatif', {'tasks': [task]})
        want(got['blocked'], f'what-if did not flag it: {got["conflicts"]}')
        task['params']['rollback'] = '1'
        pid = api.post('/api/changes', {'name': f'cut by bridge on {node.name}', 'tasks': [task]})['id']
        status, res = api.raw('POST', '/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'report', 'title': 'cut by bridge (report)'})
        demo.wait('the report', lambda: demo.finished(api, res['group']))
        want(quiet(node.name, 'ip link show sfbrcut') != 0, 'the report made the bridge')
        api.raw('POST', '/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'apply', 'title': 'cut by bridge', 'report_group': res['group']})
        time.sleep(20)
        want(not connects('sf-ctl', node.ip, 22), 'moving the interface into a bridge with no address should have cut SSH, so this proves nothing')
        t.wait_for('the timer to bring it back', lambda: connects('sf-ctl', node.ip, 22), 240)
        want(quiet(node.name, f'ip -o link show {nic} | grep -q "master sfbrcut"') != 0, 'reachable again, but the interface is still in the bridge')
        want(quiet(node.name, 'ls /etc/systemd/network/*sf-sfbrcut* >/dev/null 2>&1') != 0, 'the files of the bridge are still there')
        return f'with {kind}: it cut SSH, nothing could confirm it, and the timer put it back'
    r.check(f'bridge-cut-{kind}', node.name, run)


def networks(r, api, node, host):
    nic = primary(node)
    spare = [x for x in sudo(node.name, 'ls /sys/class/net').split() if x not in ('lo', nic) and not x.startswith(('bond', 'sfbr', 'docker', 'virbr'))]

    def bond():
        want(len(spare) >= 2, f'sf-pools should have two NICs nothing sets up: {spare}')
        ports = ','.join(spare[:2])
        plan(api, 'bond', [{'type': 'net-bond', 'host': host, 'params': {'name': 'bond0', 'ports': ports, 'mode': 'active-backup', 'address': f'{FREE_NET}.1/24'}}])
        slaves = sudo(node.name, 'cat /sys/class/net/bond0/bonding/slaves 2>/dev/null; true').split()
        want(sorted(slaves) == sorted(spare[:2]), f'the bond has {slaves}')
        sudo(node.name, 'reboot', check=False)
        time.sleep(25)
        t.wait_for('it to come back', lambda: quiet(node.name, 'true') == 0, 240)
        slaves = sudo(node.name, 'cat /sys/class/net/bond0/bonding/slaves 2>/dev/null; true').split()
        want(sorted(slaves) == sorted(spare[:2]), f'after a reboot the bond has {slaves}')
        want(quiet(node.name, f'ip -o addr show dev bond0 | grep -qF " {FREE_NET}.1/24 "') == 0, 'the bond lost its address')
        return f'bond0 over {ports} with {backend(node)}, and it survives a reboot'
    r.check('net-bond', node.name, bond)

    def config_read():
        demo.scan(api, [node.ip])
        net = api.get(f'/api/network?host={host}')['network']
        cfg = net.get('config') or {}
        want(cfg.get('manager') == 'netplan', f'the scan says the network is kept by {cfg.get("manager")}')
        b = (cfg.get('interfaces') or {}).get('bond0') or {}
        want(sorted(b.get('members') or []) == sorted(spare[:2]) and f'{FREE_NET}.1/24' in (b.get('addresses') or []), f'the bond as read: {b}')
        drawn = [n for n in api.get('/api/map?layers=network')['nodes'] if n['label'] == 'bond0' and n['host'] == host]
        want(drawn and drawn[0]['props'].get('configured_in', '').startswith('/etc/netplan/'), f'the map does not say where it is set up: {drawn}')
        return f'netplan, with bond0 set up in {b.get("source")}, and the map says so'
    r.check('net-config-read', node.name, config_read)

    def dhcp():
        _, runs = plan(api, 'dhcp', [{'type': 'net-dhcp', 'host': host, 'params': {'iface': nic, 'family': 'ipv4', 'state': 'on', 'rollback': '2'}}])
        want('FW-ROLLBACK armed 2' in said(runs), f'no timer was armed: {said(runs)[-400:]}')
        want(connects('sf-ctl', node.ip, 22), 'not reachable after DHCP on')
        want(quiet(node.name, 'systemctl list-timers --all --no-legend | grep -q sf-fw-rollback') != 0, 'the second signed run did not stop the timer')
        want(quiet(node.name, f'grep -q "dhcp4: true" /etc/netplan/90-storageforge-dhcp-{nic}.yaml') == 0, 'no netplan file of the step')
        return 'DHCP on under a timer, still reachable, and the timer stopped by the second signed run'
    r.check('net-dhcp', node.name, dhcp)


def tier26(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    nodes = roles.extra('pools')
    if not nodes:
        r.add('zfs-add', '-', None, 'no sf-pools in this build: up --join sf-pools')
    else:
        node = nodes[0]
        host, access = setup(api, node)
        if access['state'] != 'ready':
            r.add('zfs-add', node.name, False, f'deploy access is {access["state"]}', access.get('output', ''))
        else:
            d = disks(node)
            if len(d) < 6:
                r.add('zfs-add', node.name, False, f'six data disks were expected: {d}')
            else:
                pools(r, api, node, host, d)
            networks(r, api, node, host)
            address_and_route(r, api, node, host, 'netplan', 41)
            bridge_cut(r, api, node, host, 'netplan')
    # one host of the build for each other system that keeps a network
    demo.set_up_deploy_access(api)
    seen = set()
    for n, node in enumerate(roles.deployable(), 2):
        kind = backend(node)
        if kind in ('none', 'netplan') or kind in seen:
            continue
        seen.add(kind)
        host = demo.known_as(api, node.name)
        address_and_route(r, api, node, host, kind, n)
        bridge_cut(r, api, node, host, kind)
    for kind in ('nm', 'networkd', 'ifupdown'):
        if kind not in seen:
            r.add(f'net-address-{kind}', '-', None, f'no host of this build keeps its network with {kind}')
