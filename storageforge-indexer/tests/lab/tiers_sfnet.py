#!/usr/bin/env python3
"""Tier 20 of the KVM lab: StorageForge's own encrypted network (roadmap section 2.1) between real hosts and the controller.

    sfnet-make        the network made, three hosts joined, the interfaces and then the peers written by two plans, every peer
                      confirmed by key after the readings
    sfnet-keys        each host's private key is a file only root reads, and is in no deploy output and no stored record
    sfnet-reach       each host reaches the others at their network addresses
    sfnet-capture     a marker sent between two hosts over the LAN is seen in a capture, and the same marker sent over the
                      network is not: only WireGuard's UDP port carries it
    sfnet-controller  the controller a member through its link (docker-compose.sfnet.yml): the link is root with NET_ADMIN and
                      nothing else, the server stays unprivileged and does not mount the key, and both ends confirm the other
    sfnet-only-path   SSH from the controller refused on a host's LAN address: that host is still scanned, through the network
    sfnet-rotate      a host's key rotated through the plans: a new key on the host and on record, the old private key gone,
                      and the others still reach it
    sfnet-changed     a key changed by hand on a host: not taken, a critical notification, and the others stop reaching it
    sfnet-revoke      that host removed: its key off every member, its interface and key gone
    sfnet-cleanup     the network taken down again on every host and on the controller

A check reads the answer from the hosts themselves (wg, ip, ping, tcpdump there), never from StorageForge's account of its work.
Needs three deployable hosts with systemd and internet for wireguard-tools and tcpdump. tiers.py runs it. Written 2026-11-20 and
not run yet.
"""
import json
import shlex
import time

import demo
from demo import COMPOSE, ssh

import roles
from tiers_platform import install, quiet, sudo

IFACE, PORT = 'sf0', 51903
SFNET_COMPOSE = f'{COMPOSE} -f docker-compose.sfnet.yml'
LINK = 'StorageForge controller'
MARKER = 'sfclear!'                                   # eight bytes, the pattern ping fills its packets with
PATTERN = MARKER.encode().hex()


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def status(api):
    return api.get('/api/sfnet')


def row(api, host):
    return next(m for m in status(api)['members'] if m['host'] == host)


def settle(api, hosts, rounds=8):
    """Until nothing is left to do: the controller's half handed to its link, the hosts' plan saved and applied by signed run, and
    every host read again, since a reading is what confirms a key. Returns how many plans ran."""
    ran = 0
    for _ in range(rounds):
        asked = status(api)['controller'].get('pending')
        if asked:
            api.post('/api/sfnet/controller/apply', {})
            time.sleep(8)                                    # the link looks every five seconds
        made = api.post('/api/sfnet/plan', {})
        if not made['plan_id'] and not asked:
            return ran
        if made['plan_id']:
            demo.deploy(api, 'changes', made['plan_id'], made['name'])
            ran += 1
        for h in hosts:
            api.post('/api/infra/measure', {'host': h})
    raise AssertionError(f'the network did not settle in {rounds} rounds: {json.dumps(status(api))[:600]}')


def pings(vm, address, tries=4):
    """Whether vm reaches the address. A handshake sent before the other side knew this key is sent again five seconds later."""
    return quiet(vm, f'for i in $(seq 1 {tries}); do ping -c 1 -W 2 {address} >/dev/null 2>&1 && exit 0; sleep 2; done; exit 1') == 0


def lan_iface(vm, ip):
    return sudo(vm, f"ip -o -4 addr show | awk -v a={ip} 'index($4, a \"/\") == 1 {{print $2; exit}}'").strip()


def tier20(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    nodes = [n for n in roles.deployable() if not n.can('nosystemd')][:3]
    if len(nodes) < 3:
        r.add('sfnet-make', '-', None, 'needs three deployable hosts with systemd in the build')
        return
    a, b, c = nodes
    name = {n.name: demo.known_as(api, n.name) for n in nodes}
    hosts = [name[n.name] for n in nodes]
    ctl_ip = roles.build()['sf-ctl'].ip
    on = {}                                                   # host -> its address on the network
    in_app = lambda code: ssh('sf-ctl', f'{COMPOSE} exec -T storageforge python -c {shlex.quote(code)}')      # noqa: E731

    def make():
        for n in nodes:
            install(n, 'wireguard-tools')
            install(n, 'tcpdump')
            want(quiet(n.name, 'modprobe wireguard') == 0, f'{n.name} has no WireGuard in its kernel')
        made = api.post('/api/sfnet', {})
        want(made['network']['port'] == PORT, made)
        net = made['network']['range']
        for n in nodes:
            addrs = sudo(n.name, 'ip -o -4 addr show').split()
            want(not any(x.startswith(net.rsplit('.', 2)[0] + '.') and '/' in x for x in addrs), f'the range {net} is in use on {n.name}')
            on[name[n.name]] = api.post('/api/sfnet/members', {'host': name[n.name]})['address']
        for h in hosts:
            api.post('/api/infra/measure', {'host': h})
        plans = settle(api, hosts)
        want(plans == 2, f'{plans} plans ran: the interfaces, then the peers, is two')
        got = {m['host']: (m['state'], m['missing'], m['unknown']) for m in status(api)['members']}
        want(all(got[h] == ('ok', [], []) for h in hosts), got)
        for n in nodes:
            mine = sudo(n.name, f'wg show {IFACE} public-key').strip()
            want(mine == row(api, name[n.name])['public_key'], f'{n.name}: the key on record is not the key on the host')
            want(len(sudo(n.name, f'wg show {IFACE} peers').split()) == 2, f'{n.name} does not have two peers')
        return f'{net}, three members, every peer confirmed by key in two plans'
    r.check('sfnet-make', a.name, make)
    if not on:
        return

    def keys():
        for n in nodes:
            mode = sudo(n.name, f'stat -c "%a %U" /etc/wireguard/{IFACE}.key').strip()
            want(mode == '600 root', f'{n.name}: the key file is {mode}')
            want(quiet(n.name, f'grep -q PrivateKey /etc/wireguard/{IFACE}.conf') != 0, f'{n.name}: the configuration holds a copy of the private key')
            private = sudo(n.name, f'cat /etc/wireguard/{IFACE}.key').strip()
            found = in_app("import sqlite3; c = sqlite3.connect('/app/data/index.db'); k = " + repr(private) + "; "
                           "print(sum(k in str(r[0] or '') for t, col in (('deploy_runs', 'output'), ('settings', 'value_json'), ('security_measurements', 'data_json')) "
                           "for r in c.execute('SELECT ' + col + ' FROM ' + t)))").strip()
            want(found == '0', f'the private key of {n.name} is in the index {found} time(s)')
        return 'three keys, each root-only on its host, none in a deploy output, a setting or a reading'
    r.check('sfnet-keys', a.name, keys)

    def reach():
        for x in nodes:
            for y in nodes:
                if x is not y:
                    want(pings(x.name, on[name[y.name]]), f'{x.name} does not reach {y.name} at {on[name[y.name]]}')
        return 'every host reaches the other two across the network'
    r.check('sfnet-reach', a.name, reach)

    def capture():
        dev = lan_iface(b.name, b.ip)
        want(dev, f'no interface on {b.name} has {b.ip}')

        def seen(target):
            """Capture on b's LAN interface while a pings the target with the marker in every packet: (packets from a, whether the marker shows)."""
            sudo(b.name, f'rm -f /tmp/sfnet.cap; (timeout 12 tcpdump -i {dev} -n -A -c 40 host {a.ip} and not port 22 >/tmp/sfnet.cap 2>/dev/null &) ; sleep 2')
            quiet(a.name, f'ping -c 4 -W 2 -p {PATTERN} {target} >/dev/null')
            time.sleep(11)
            text = sudo(b.name, 'cat /tmp/sfnet.cap; rm -f /tmp/sfnet.cap')
            return text.count(' IP '), MARKER in text, text
        packets, clear, _ = seen(b.ip)
        want(packets and clear, f'the capture did not see the marker sent in the clear over the LAN ({packets} packets): the check would prove nothing')
        packets, clear, text = seen(on[name[b.name]])
        want(packets, 'nothing was captured between the two hosts while one pinged the other over the network')
        want(not clear, 'the marker crossed the LAN in clear text')
        want(f'.{PORT}' in text and 'ICMP' not in text, f'what crossed was not only UDP {PORT}: {text[:300]}')
        return f'{packets} packets on {dev}, all UDP {PORT}, the marker in none; in the clear over the LAN it shows'
    r.check('sfnet-capture', b.name, capture)

    def controller():
        ssh('sf-ctl', f'{SFNET_COMPOSE} up -d --no-build --wait --quiet-pull')
        # Recreating the controller invalidates the session used for initial setup.
        api.post('/api/login', {'username': 'demo', 'password': api.password})
        info = ssh('sf-ctl', "sudo -n docker inspect --format '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.CapAdd}} {{.HostConfig.Privileged}}' storageforge-sfnet-1").strip()
        want(info in ('0:0 true [ALL] [NET_ADMIN] false', '0:0 true [ALL] [CAP_NET_ADMIN] false'), f'the link runs as: {info}')
        server = ssh('sf-ctl', "sudo -n docker inspect --format '{{.Config.User}} {{.HostConfig.CapAdd}} {{range .Mounts}}{{.Name}} {{end}}' storageforge-storageforge-1").strip()
        want(server.startswith('10001:10001 []') and 'sfnet-keys' not in server, f'the server runs as: {server}')
        want(quiet('sf-ctl', f'{COMPOSE} exec -T storageforge ls /etc/wireguard/{IFACE}.key') != 0, 'the server can see the key file')
        me = api.post('/api/sfnet/controller', {})
        on[LINK] = me['address']
        settle(api, hosts)
        got = status(api)
        want(got['controller']['running'] and not got['controller']['pending'] and not got['controller']['error'], got['controller'])
        states = {m['host']: (m['state'], m['missing']) for m in got['members']}
        want(all(states[h] == ('ok', []) for h in [*hosts, LINK]), states)
        want(sudo('sf-ctl', f'{SFNET_COMPOSE} exec -T sfnet wg show {IFACE} public-key').strip() == row(api, LINK)['public_key'], 'the key on record is not the link\'s')
        private = sudo('sf-ctl', f'{SFNET_COMPOSE} exec -T sfnet cat /etc/wireguard/{IFACE}.key').strip()
        files = ssh('sf-ctl', f'{COMPOSE} exec -T storageforge sh -c "cat /run/sf-sfnet-want/* /run/sf-sfnet-state/*"')
        want(private and private not in files, 'the private key is in a file the server can read')
        for n in nodes:
            want(pings(n.name, on[LINK]), f'{n.name} does not reach the controller at {on[LINK]}')
        return f'a member at {on[LINK]}; the link is {info}; the server holds no key'
    r.check('sfnet-controller', 'sf-ctl', controller)

    def only_path():
        want(LINK in on, 'the controller is not a member')
        rule = f'INPUT ! -i {IFACE} -p tcp --dport 22 -s {ctl_ip} -j DROP'
        sudo(a.name, f'iptables -I {rule}')
        try:
            probe = ("import socket, sys\n"
                     "def up(a):\n"
                     "    try:\n"
                     "        socket.create_connection((a, 22), timeout=4).close(); return 1\n"
                     "    except OSError:\n"
                     "        return 0\n"
                     f"print(up('{a.ip}'), up('{on[name[a.name]]}'))")
            want(in_app(probe).split() == ['0', '1'], 'SSH from the controller is not refused on the LAN address and open on the network address')
            before = sudo(a.name, f'wg show {IFACE} transfer')
            demo.scan(api, [a.ip])                            # fails, and says so, if the host cannot be reached
            api.post('/api/infra/measure', {'host': name[a.name]})
            want(sudo(a.name, f'wg show {IFACE} transfer') != before, 'nothing crossed the network during the scan')
            routes = api.get(f'/api/console/hosts/{name[a.name]}')['routes']
            want(routes[0]['route'] == 'storageforge' and routes[0]['label'] == 'the StorageForge network' and routes[0]['address'] == on[name[a.name]], routes)
        finally:
            sudo(a.name, f'iptables -D {rule}', check=False)
        return f'SSH from {ctl_ip} dropped on the LAN, and {a.name} was scanned and read over the network'
    r.check('sfnet-only-path', a.name, only_path)

    def rotate():
        old_public = sudo(a.name, f'wg show {IFACE} public-key').strip()
        old_private = sudo(a.name, f'cat /etc/wireguard/{IFACE}.key').strip()
        api.post('/api/sfnet/members/rotate', {'host': name[a.name]})
        plans = settle(api, hosts)
        new_public = sudo(a.name, f'wg show {IFACE} public-key').strip()
        want(new_public != old_public and row(api, name[a.name])['public_key'] == new_public, 'the key did not change on the host and on record')
        want(row(api, name[a.name])['rotation'] is None and row(api, name[a.name])['state'] == 'ok', row(api, name[a.name]))
        want(quiet(a.name, f'grep -rqF {shlex.quote(old_private)} /etc/wireguard') != 0, 'the old private key is still on the host')
        for n in (b, c):
            peers = sudo(n.name, f'wg show {IFACE} peers').split()
            want(new_public in peers and old_public not in peers, f'{n.name} does not hold the new key alone')
            want(pings(n.name, on[name[a.name]]), f'{n.name} no longer reaches {a.name}')
        return f'rotated in {plans} plans, the old key gone from the host and from every peer'
    r.check('sfnet-rotate', a.name, rotate)

    def changed():
        on_record = row(api, name[b.name])['public_key']
        sudo(b.name, f'umask 077; wg genkey >/root/sfnet-by-hand.key; wg set {IFACE} private-key /root/sfnet-by-hand.key')
        api.post('/api/infra/measure', {'host': name[b.name]})
        got = row(api, name[b.name])
        want(got['key_changed'] and got['public_key'] == on_record, f'the changed key was not reported, or was taken: {got}')
        want(any(g.get('kind') == 'sfnet-key' and g.get('level') == 'crit' for g in api.get('/api/notifications')['groups']), 'no critical notification')
        want(not pings(a.name, on[name[b.name]], tries=2), f'{a.name} still reaches a host that shows another key')
        sudo(b.name, 'rm -f /root/sfnet-by-hand.key')
        return 'reported as critical, not taken, and the others stopped reaching it'
    r.check('sfnet-changed', b.name, changed)

    def revoke():
        gone = row(api, name[b.name])['public_key']
        api.post('/api/sfnet/members/remove', {'host': name[b.name]})
        settle(api, hosts)
        for n in (a, c):
            want(gone not in sudo(n.name, f'wg show {IFACE} peers'), f'{n.name} still holds the key of {b.name}')
        want(quiet(b.name, f'ip link show dev {IFACE}') != 0, f'{b.name} still has {IFACE}')
        want(quiet(b.name, f'test -e /etc/wireguard/{IFACE}.key') != 0, f'{b.name} still has its key')
        want(pings(a.name, on[name[c.name]]), 'the members that stayed lost each other')
        return 'its key is off every member, and its interface and key are gone'
    r.check('sfnet-revoke', b.name, revoke)

    def cleanup():
        for h in (name[a.name], name[c.name], LINK):
            api.post('/api/sfnet/members/remove', {'host': h})
        settle(api, hosts)
        for n in nodes:
            want(quiet(n.name, f'ip link show dev {IFACE}') != 0, f'{n.name} still has {IFACE}')
        want(quiet('sf-ctl', f'{SFNET_COMPOSE} exec -T sfnet ip link show dev {IFACE}') != 0, 'the controller still has its interface')
        return 'no host and no controller has the interface any more'
    r.check('sfnet-cleanup', a.name, cleanup)
