#!/usr/bin/env python3
"""Tier 12 of the KVM lab: real routers on isolated networks. A real RouterOS CHR and a real OpenWrt, with real machines on their LAN, DMZ and WAN.

What StorageForge says is compared with what the router says and with what real packets do: curl between the VMs is the check on the path query, and the rollback tests really do cut StorageForge off.
No free Cisco or pfSense image exists for this lab, so those adapters are tested only against published formats (tests/test_routers.py), and this tier says so.

    SFLAB_ONLY=rollback,scanner tiers.py run 12       just these, by what their names start with
"""
import json
import os
import re
import shlex
import subprocess
import time

import demo
import roles
from demo import COMPOSE, ssh

from tiers_platform import sudo

ONLY = [x for x in os.environ.get('SFLAB_ONLY', '').split(',') if x]
LAN, DMZ, WAN = '10.77.10.50', '10.77.20.80', '198.51.100.50'
ROS_WAN, WRT_WAN = '198.51.100.1', '198.51.100.2'


def want(ok, text):
    if not ok:
        demo.fail(text)


def router_ssh(ip, command, user='lab', timeout=30):
    """The lab's own way in, from this machine: what the router itself says, not what StorageForge reports of it."""
    p = subprocess.run(['ssh', '-i', f'{demo.STATE}/id_ed25519', '-o', f'UserKnownHostsFile={demo.STATE}/known_hosts', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'LogLevel=ERROR', f'{user}@{ip}', command],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f'{ip}: {command}: {p.stderr[-200:] or p.returncode}')
    return p.stdout


def curl(vm, url, timeout=5):
    """(worked, body): real packets across the router."""
    p = subprocess.run([demo.LAB, 'ssh', vm, f'curl -s -m {timeout} {shlex.quote(url)}'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout + 30)
    return p.returncode == 0, p.stdout.strip()


def in_container(command, stdin=None):
    return ssh('sf-ctl', f'{COMPOSE} exec -T storageforge sh -c {shlex.quote(command)}', stdin=stdin)




def measure_by_hand(node):
    """Alpine takes no signed deploys, so its firewall reading comes through the same script and parser, by the lab's own SSH."""
    from storageforge_index import inframeasure
    data = inframeasure.parse(sudo(node.name, inframeasure.script()))
    want(data is not None, 'the reading was cut short')
    script = "import json,sys,time\nfrom storageforge_index import security,infragraph,cli\nfrom storageforge_index.db import Database\nimport os\ndb=Database(os.environ['STORAGEFORGE_DB'])\nc=db.connect()\nsecurity._save_measurement(c,sys.argv[1],'infra',int(time.time()),'measure',json.load(sys.stdin))\ninfragraph.rebuild(c,sys.argv[1])\nc.close()\n"
    ssh('sf-ctl', f'{COMPOSE} exec -T storageforge python -c {shlex.quote(script)} {node.name}', stdin=json.dumps(data))


def bind(key, host, user, actions):
    """Run again on the same database, a binding is there already."""
    p = subprocess.run([demo.LAB, 'ssh', 'sf-ctl', f'{COMPOSE} exec -T storageforge storageforge-index vault bind --key {key} --host {host} --user {user} --actions {actions}'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
    want(p.returncode == 0 or 'already' in p.stderr + p.stdout or 'UNIQUE' in p.stderr + p.stdout or 'unique' in p.stderr + p.stdout, f'bind {key} to {host}: {p.stderr[-300:]}')


def tier12(r):
    lab = roles.network_lab()
    mikrotik, openwrt = lab.get('sf-mikrotik'), lab.get('sf-openwrt')
    client, server, outside = lab.get('sf-lan-client'), lab.get('sf-dmz-server'), lab.get('sf-wan-host')
    if not mikrotik:
        r.add('network-lab', '-', None, 'this build has no routers: lab.sh up --join sf-mikrotik,sf-openwrt,sf-wan-host,sf-lan-client,sf-dmz-server')
        return
    ros_ip, wrt_ip = mikrotik.ip, openwrt.ip if openwrt else None

    def check(name, host, fn):
        if ONLY and not any(name.startswith(x) for x in ONLY):
            return
        started = time.time()
        try:
            note = fn()
            r.add(name, host, True, f'{note or ""} ({time.time() - started:.0f} s)'.strip())
        except Exception as exc:
            r.add(name, host, False, f'{type(exc).__name__}: {str(exc)[:240]}')

    api = demo.sign_in()
    # ── set up as an operator would: keys in the vault, on the device, bound to its address ──
    have = {k['name'] for k in api.get('/api/keys')['keys']}
    for key in ('lab-net-read', 'lab-net-admin', 'lab-scan'):
        if key not in have:
            api.post('/api/keys', {'name': key})
    keys = {k['name']: k['public_key'] for k in api.get('/api/keys')['keys']}

    def enrol():
        for user, key in (('scan', 'lab-net-read'), ('lab', 'lab-net-admin')):
            router_ssh(ros_ip, f'/file/add name=sf-{user}.pub contents="{keys[key]}"')
            router_ssh(ros_ip, f'/user/ssh-keys/import public-key-file=sf-{user}.pub user={user}')
        bind('lab-net-read', ros_ip, 'scan', 'scan')
        bind('lab-net-admin', ros_ip, 'lab', 'deploy')
        got = api.post('/api/devices', {'name': 'sf-mikrotik', 'platform': 'routeros', 'address': ros_ip, 'wan': ['ether2']})
        want(got['platform'] == 'routeros', got)
        if openwrt:
            # OpenWrt's firewall and ubus want root: the same account reads and changes, which is why RouterOS's split is worth having
            router_ssh(wrt_ip, f'echo {shlex.quote(keys["lab-net-read"])} >> /etc/dropbear/authorized_keys; echo {shlex.quote(keys["lab-net-admin"])} >> /etc/dropbear/authorized_keys')
            bind('lab-net-read', wrt_ip, 'root', 'scan')
            bind('lab-net-admin', wrt_ip, 'root', 'deploy')
            api.post('/api/devices', {'name': 'sf-openwrt', 'platform': 'openwrt', 'address': wrt_ip})
    check('enrol-devices', '-', enrol)

    # ── 12.0: the transports, against the real thing ──
    def read(name):
        def fn():
            got = api.post(f'/api/devices/{name}/read', {})
            want(got['ok'], got.get('error'))
            return f'{got["os"]}: {got["interfaces"]} interfaces, {got["routes"]} routes, {got["rules"]} rules, {got["nat"]} NAT'
        return fn
    check('transport-ssh', 'sf-mikrotik', read('sf-mikrotik'))
    if openwrt:
        check('transport-ssh', 'sf-openwrt', read('sf-openwrt'))

    def read_only():
        p = subprocess.run(['ssh', '-i', f'{demo.STATE}/id_ed25519', '-o', f'UserKnownHostsFile={demo.STATE}/known_hosts', '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', f'scan@{ros_ip}', '/system/identity/set name=hacked'], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=20)
        want('not enough permissions' in p.stdout + p.stderr, f'the read account could write: {p.stdout!r} {p.stderr!r}')
        want(router_ssh(ros_ip, ':put [/system/identity/get name]').strip() == 'sf-mikrotik', 'its name changed')
        return 'the account StorageForge reads with was refused a write, by the router'
    check('transport-read-account', 'sf-mikrotik', read_only)

    def password():
        pw = (demo.STATE / 'sf-mikrotik-password').read_text().strip()
        api.post('/api/devices/credentials', {'name': 'net-telnet', 'username': 'lab', 'password': pw})
        creds = api.get('/api/devices/credentials')['credentials']
        want(any(c['name'] == 'net-telnet' for c in creds) and pw not in json.dumps(creds), 'the credential list holds the password')
        got = api.post('/api/devices', {'name': 'sf-mikrotik-telnet', 'platform': 'routeros', 'address': ros_ip, 'transport': 'telnet', 'credential': 'net-telnet'})
        want(not got['encrypted'], 'Telnet was not called unencrypted')
        out = api.post('/api/devices/sf-mikrotik-telnet/read', {})
        want(out['ok'], out.get('error'))
        warn = [w for w in api.get('/api/map/coverage')['device_warnings'] if w['device'] == 'sf-mikrotik-telnet']
        want(warn and 'Telnet' in warn[0]['text'], 'no warning about Telnet')
        api('DELETE', '/api/devices/sf-mikrotik-telnet')
        logs = in_container('grep -rl -F ' + shlex.quote(pw) + ' /var/log 2>/dev/null | head -3 || true')
        want(not logs.strip(), f'the password is in {logs}')
        return f'read a real router over Telnet: {out["interfaces"]} interfaces, the password nowhere in its logs'
    check('transport-telnet', 'sf-mikrotik', password)

    def password_over_ssh():
        # RouterOS refuses a password for an account that has an SSH key, so this is an account with none, as a device reached by password would have
        pw = (demo.STATE / 'sf-mikrotik-password').read_text().strip()
        router_ssh(ros_ip, f'/user/add name=sfpw group=sf-read password={pw}')
        try:
            api.post('/api/devices/credentials', {'name': 'net-ssh', 'username': 'sfpw', 'password': pw})
            api.post('/api/devices', {'name': 'sf-mikrotik-pw', 'platform': 'routeros', 'address': ros_ip, 'credential': 'net-ssh'})
            refused = api.raw('POST', '/api/devices/sf-mikrotik-pw/read', {})
            want(refused[0] == 409 and 'host key' in refused[1]['error'], f'a password went out with no key confirmed: {refused}')
            offered = api.post('/api/devices/sf-mikrotik-pw/hostkey', {})['keys']
            want(offered, 'the router offered no host key')
            for k in offered:
                api.post('/api/devices/sf-mikrotik-pw/hostkey', {'confirm': k['fingerprint']})
            out = api.raw('POST', '/api/devices/sf-mikrotik-pw/read', {})[1]
            want(out['ok'], out.get('error'))
            return f'refused until a person confirmed the host key, then read over SSH with a password: {out["interfaces"]} interfaces'
        finally:
            api.raw('DELETE', '/api/devices/sf-mikrotik-pw')
            api.raw('DELETE', '/api/devices/credentials/net-ssh')
            router_ssh(ros_ip, '/user/remove [find name=sfpw]')
    check('transport-password', 'sf-mikrotik', password_over_ssh)

    def terminal():
        from storageforge_index.nettransport import NetworkTransport
        t = NetworkTransport(ros_ip, 'scan', profile='routeros', key=str(demo.STATE / 'id_ed25519'), known_hosts=str(demo.STATE / 'known_hosts'), command_timeout=20)
        try:
            out = t.run('/system/identity/print')
            want('sf-mikrotik' in out, f'said {out!r}')
            many = t.run('/ip/address/print')
            want('10.77.10.1' in many and '[' not in many.splitlines()[-1], f'said {many!r}')
        finally:
            t.close()
        return 'an interactive RouterOS terminal: found its prompt, ran commands, no prompt left in the output'
    check('transport-terminal', 'sf-mikrotik', terminal)
    r.add('transport-cisco-pfsense', '-', None, 'no free Cisco or pfSense image for this lab: those adapters have only met published formats')

    # ── 12.1: what it read, against what the router says ──
    def facts():
        got = api.get('/api/devices/sf-mikrotik')
        real = json.loads(router_ssh(ros_ip, ':put [:serialize to=json [/interface/print as-value]]'))
        names = {i['name']: i for i in got['network']['interfaces']}
        want({i['name'] for i in real} == set(names), f'{sorted(names)} against {[i["name"] for i in real]}')
        for i in real:
            want(names[i['name']]['mac'] == (None if i['mac-address'] == '00:00:00:00:00:00' else i['mac-address'].lower()), f'{i["name"]} MAC')
        addrs = {a['ip'] for i in got['network']['interfaces'] for a in i['addresses']}
        want({ROS_WAN, '10.77.10.1', '10.77.20.1', ros_ip} <= addrs, addrs)
        routes = json.loads(router_ssh(ros_ip, ':put [:serialize to=json [/ip/route/print as-value]]'))
        want(len([x for x in got['network']['routes'] if x['family'] == 4]) == len([x for x in routes if x.get('active')]), 'routes differ')
        vlan = names['vlan20']
        want((vlan['kind'], vlan['vlan_id'], vlan['parent']) == ('vlan', 20, 'br-test'), vlan)
        want(any(x['ip'] == '10.77.10.50' for x in got['facts']['leases']), 'its DHCP lease')
        return f'{len(names)} interfaces, {len(addrs)} addresses, {len(routes)} routes, as the router reports them'
    check('facts-routeros', 'sf-mikrotik', facts)

    if openwrt:
        def wrt_facts():
            got = api.get('/api/devices/sf-openwrt')
            real = router_ssh(wrt_ip, 'ubus call network.interface dump')
            for iface in json.loads(real)['interface']:
                for a in iface.get('ipv4-address') or []:
                    want(any(x['ip'] == a['address'] for i in got['network']['interfaces'] for x in i['addresses']), f'{a["address"]} is missing')
            want(got['facts']['wan'] == ['eth1'], got['facts']['wan'])
            want(got['firewall']['backends'] == ['nftables'], got['firewall']['backends'])
            return f'{len(got["network"]["interfaces"])} interfaces, {len(got["firewall"]["rules"])} fw4 rules'
        check('facts-openwrt', 'sf-openwrt', wrt_facts)

    def map_nodes():
        g = api.get('/api/map?layers=network,services,firewall')
        got = [n for n in g['nodes'] if n['host'] == 'sf-mikrotik']
        want(any(n['kind'] == 'NIC' for n in got), 'no interfaces on the map')
        want(any(n['kind'] == 'Bridge' for n in got) and any(n['kind'] == 'VLAN' for n in got), 'no bridge or VLAN on the map')
        host = next((n for n in g['nodes'] if n['kind'] == 'Host' and n['label'] == 'sf-mikrotik'), None)
        want(host and host['props'].get('device') == 'routeros', f'the router on the map: {host}')
        return f'{len(got)} nodes'
    check('map-shows-router', 'sf-mikrotik', map_nodes)

    # ── 12.2: every backend into one model, deciding the same ──
    if openwrt:
        def same():
            ask = {'proto': 'tcp', 'daddr': DMZ, 'saddr': LAN, 'family': 'ip'}
            from storageforge_index import exposure
            out = {}
            for name, iif, oif in (('sf-mikrotik', 'ether3', 'ether4'), ('sf-openwrt', 'eth2', 'eth3')):
                fw = api.get(f'/api/devices/{name}')['firewall']
                out[name] = [exposure.kernel_path(fw, 'forward', {**ask, 'port': p, 'iif': iif, 'oif': oif})['verdict'] for p in (80, 22, 443)]
            want(out['sf-mikrotik'] == out['sf-openwrt'] == ['accept', 'drop', 'drop'], out)
            return 'RouterOS filter and fw4 nftables decide alike: 80 through, 22 and 443 stopped'
        check('normalized-alike', '-', same)

    # ── 12.3: the path query, against real packets ──
    def segment_hosts():
        for node in (client, server, outside):
            demo.install_key(node.name, 'scan', keys['lab-scan'])
            sudo(node.name, 'apk add -q findutils util-linux coreutils tar iproute2')
            bind('lab-scan', node.ip, 'scan', 'scan,checksum')
        demo.scan(api, [client.ip, server.ip, outside.ip])
        for node in (client, server, outside):
            measure_by_hand(node)
    check('segments-scanned', '-', segment_hosts)
    api.post('/api/devices/sf-mikrotik/read', {})

    def path(src, dst, port, want_verdict, vm, url, works):
        def fn():
            got = api.get(f'/api/map/reach?from={src}&to={dst}&port={port}')
            want(got['verdict'] == want_verdict, f'said {got["verdict"]}: {got.get("decided_by")} {got.get("blind_spots")}')
            real, body = curl(vm, url)
            want(real == works, f'real curl {"worked" if real else "failed"} ({body!r}), and it said {got["verdict"]}')
            return f'{got["verdict"]} by {got.get("decided_by")}, and real curl {"reached it" if real else "was stopped"}'
        return fn
    check('reach-allowed-matches-curl', 'sf-mikrotik', path(LAN, DMZ, 80, 'allowed', client.name, f'http://{DMZ}/', True))
    check('reach-blocked-matches-curl', 'sf-mikrotik', path(LAN, DMZ, 443, 'blocked', client.name, f'http://{DMZ}:443/', False))

    def flip():
        rid = next(x['.id'] for x in json.loads(router_ssh(ros_ip, ':put [:serialize to=json [/ip/firewall/filter/print as-value]]')) if x.get('comment') == 'lan-to-dmz-web')
        router_ssh(ros_ip, f'/ip/firewall/filter/set {rid} action=drop')
        try:
            api.post('/api/devices/sf-mikrotik/read', {})
            got = api.get(f'/api/map/reach?from={LAN}&to={DMZ}&port=80')
            want(got['verdict'] == 'blocked' and 'sf-mikrotik' in got['decided_by'], got)
            real, _ = curl(client.name, f'http://{DMZ}/')
            want(not real, 'curl still got through')
            return f'after the rule changed: {got["decided_by"]}, and curl was stopped too'
        finally:
            router_ssh(ros_ip, f'/ip/firewall/filter/set {rid} action=accept')
            api.post('/api/devices/sf-mikrotik/read', {})
    check('reach-flips-with-the-rule', 'sf-mikrotik', flip)

    def through_forward():
        got = api.get(f'/api/map/reach?from={WAN}&to={ROS_WAN}&port=443')
        want(got['verdict'] == 'allowed' and got.get('forwarded_to') == f'{DMZ}:443', got)
        real, body = curl(outside.name, f'http://{ROS_WAN}:443/')
        want(real and body == 'dmz-server', f'real curl: {real} {body!r}')
        return f'allowed through the forward to {got["forwarded_to"]}, and curl from the WAN got “{body}”'
    check('reach-through-port-forward', 'sf-mikrotik', through_forward)

    # ── 12.4: exposure ──
    def exposed():
        rep = api.get(f'/api/exposure?host={server.name}')['hosts'][0]
        by = {i['port']: i for i in rep['items']}
        want(by[443]['level'] == 'any' and 'sf-mikrotik' in by[443]['rule'], by[443])
        want(by[80]['level'] == 'lan', by[80])
        other = api.get(f'/api/exposure?host={client.name}')['hosts'][0]
        got = next(i for i in other['items'] if i['port'] == 8080)
        want(got['level'] == 'lan', got)
        real, body = curl(outside.name, f'http://{ROS_WAN}:8080/', 3)
        want(not real, 'the LAN service is reachable from outside after all')
        return '443 on the DMZ server: any, through the forward. 80 there and 8080 on the LAN client: private networks. A real curl from the WAN agrees'
    check('exposure-through-router', server.name, exposed)

    # ── 12.5: the language, compiled and given to the real tools ──
    TEXT = '/ip firewall address-list add list=sf-test address=10.99.0.0/16\n/ip firewall filter add chain=input protocol=tcp dst-port=9099 src-address=10.99.0.0/16 action=accept comment="sf test"\n/ip firewall filter add chain=forward in-interface=eth9 protocol=tcp dst-port=9100,9101 action=drop\n/ip firewall nat add chain=dstnat in-interface=eth9 protocol=tcp dst-port=9102 action=dst-nat to-addresses=10.99.0.1 to-ports=80\n'

    def compiled(target):
        return api.post('/api/dsl/compile', {'dsl': TEXT, 'targets': [target]})['targets'][target]

    def real_nft():
        host = roles.deployable()[0]
        text = compiled('nftables')['text']
        sudo(host.name, 'command -v nft >/dev/null || { command -v apt-get >/dev/null && apt-get -qq install -y nftables || dnf -q -y install nftables || zypper -nq install nftables; }; true')
        sudo(host.name, f"printf %s {shlex.quote(text.replace('delete table inet storageforge_dsl', '').replace('delete table ip storageforge_dsl_nat', ''))} > /tmp/sf-dsl.nft; nft -c -f /tmp/sf-dsl.nft")
        return f'nft -c on {host.name} takes it'
    check('compile-nftables', '-', real_nft)

    def real_ipt():
        host = next((n for n in roles.deployable() if quiet_has(n.name, 'iptables-restore')), None)
        if host is None:
            r.add('compile-iptables', '-', None, 'no host here has iptables-restore')
            return 'skipped'
        text = compiled('iptables')
        want(any('address-list' in u['statement'] or 'address' in u['why'] for u in text['unsupported']), 'should have said it left out the address list')
        sudo(host.name, f"printf %s {shlex.quote(text['text'])} | iptables-restore --test --noflush")
        return f'iptables-restore --test on {host.name} takes it, and it said it left out the address list'
    check('compile-iptables', '-', real_ipt)

    def real_routeros():
        got = api.post('/api/devices/sf-mikrotik/report', {'dsl': '/ip firewall address-list add list=sf-test address=10.99.0.0/16 comment="from the language"'})
        want(got['can_apply'], got)
        return 'reported'
    check('compile-routeros', 'sf-mikrotik', real_routeros)

    def back_to_dsl():
        out = {}
        for name in ('sf-mikrotik', 'sf-openwrt', client.name):
            text = api.get(f'/api/dsl/of?host={name}')['dsl']
            want('/ip address add' in text, f'{name}: {text[:200]}')
            out[name] = len(text.splitlines())
        text = api.get('/api/dsl/of?host=sf-mikrotik')['dsl']
        want('comment=lan-to-dmz-web' in text and 'chain=forward' in text and 'to-addresses=10.77.20.80' in text, text)
        return f'lines of the one language: {out}'
    check('normalize-to-dsl', '-', back_to_dsl)

    # ── 12.6: a change, a change that cuts StorageForge off, and the way back ──
    def wait_change(cid, *states, secs=420):
        until = time.time() + secs
        while time.time() < until:
            c = api.get(f'/api/devices/changes/{cid}')
            if c['status'] in states:
                return c
            time.sleep(4)
        demo.fail(f'still {c["status"]} after {secs} s')

    def keep(name, ip, dsl, verify):
        def fn():
            rep = api.post(f'/api/devices/{name}/report', {'dsl': dsl})
            want(rep['can_apply'], rep)
            api.post(f'/api/devices/changes/{rep["id"]}/apply', {'rollback': 120})
            c = wait_change(rep['id'], 'confirmed', 'rolled-back', 'lost', 'rolling-back', secs=200)
            want(c['status'] == 'confirmed', f'it ended as {c["status"]}: {c.get("output")}')
            return verify()
        return fn

    def ros_verify():
        want('sf-kept' in router_ssh(ros_ip, ':put [:serialize to=json [/ip/firewall/address-list/print as-value]]'), 'the entry is not on the router')
        want('sf-' not in router_ssh(ros_ip, ':put [:serialize to=json [/system/scheduler/print as-value]]'), 'the timer is still set')
        return 'on the router, and the timer gone'
    check('apply-and-keep', 'sf-mikrotik', keep('sf-mikrotik', ros_ip, '/ip firewall address-list add list=sf-kept address=10.98.0.0/16', ros_verify))

    if openwrt:
        def wrt_verify():
            want('sf-kept-rule' in router_ssh(wrt_ip, 'uci show firewall'), 'the rule is not in UCI')
            want('sf-kept-rule' in router_ssh(wrt_ip, 'nft list ruleset'), 'the rule did not reach the kernel')
            return 'in UCI and in the kernel, and the timer gone: ' + str(router_ssh(wrt_ip, 'ls /tmp | grep -c "^sf-" || true').strip())
        check('apply-and-keep', 'sf-openwrt', keep('sf-openwrt', wrt_ip, '/ip firewall filter add chain=forward in-interface=lan1 out-interface=dmz protocol=tcp dst-port=8081 action=accept comment="sf-kept-rule"', wrt_verify))

    def cut(name, ip, dsl, probe, marker):
        def fn():
            before = api.get(f'/api/devices/{name}')['firewall']['rules']
            rep = api.post(f'/api/devices/{name}/report', {'dsl': dsl})
            want(rep['can_apply'], rep)
            res = api.post(f'/api/devices/changes/{rep["id"]}/apply', {'rollback': 90})
            want(res['ok'], res)
            time.sleep(25)
            dead = False
            try:
                router_ssh(ip, probe, timeout=8)
            except (RuntimeError, subprocess.TimeoutExpired):
                dead = True
            want(dead, 'the change did not cut SSH off: this proves nothing')
            c = wait_change(rep['id'], 'rolled-back', 'lost', 'confirmed', secs=500)
            want(c['status'] == 'rolled-back', f'it ended as {c["status"]}: {c.get("output")}')
            router_ssh(ip, probe)
            want(marker not in json.dumps(api.get(f'/api/devices/{name}')['firewall']['rules']), 'the rule is still there')
            want(len(api.get(f'/api/devices/{name}')['firewall']['rules']) == len(before), 'the rules are not what they were')
            return f'SSH really went dead, the router put itself back after {int(c["finished_at"] - c["applied_at"])} s, and StorageForge is back in'
        return fn
    check('rollback-routeros', 'sf-mikrotik', _cut_first(api, router_ssh, ros_ip))
    if openwrt:
        check('rollback-openwrt', 'sf-openwrt', cut('sf-openwrt', wrt_ip, '/ip firewall filter add chain=input in-interface=mgmt protocol=tcp dst-port=22 action=drop comment="sf-cut"', 'echo ok', 'sf-cut'))

    # ── the scanner, off and then on ──
    def capture(seconds=45):
        node = server
        if subprocess.run([demo.LAB, 'ssh', node.name, 'command -v tcpdump'], capture_output=True, stdin=subprocess.DEVNULL).returncode:
            sudo(node.name, 'apk add -q tcpdump')
        sudo(node.name, f'rm -f /tmp/cap.txt; nohup timeout {seconds} tcpdump -nn -q -i eth0 src 10.77.0.10 >/tmp/cap.txt 2>/dev/null &')
        time.sleep(3)
        return node

    def off_means_off():
        want(api.get('/api/netscan')['settings']['enabled'] is False, 'it started on')
        try:
            api.post('/api/netscan/run', {})
            demo.fail('it ran with the scanner off')
        except demo.DemoError as exc:
            want('off' in str(exc), exc)
        node = capture(25)
        api.post('/api/devices/sf-mikrotik/read', {})
        time.sleep(25)
        sudo(node.name, 'pkill tcpdump; sleep 1; true')
        seen = sudo(node.name, 'cat /tmp/cap.txt')
        want(not seen.strip(), f'the controller sent it packets: {seen[:200]}')
        return 'with the scanner off, the machine it never manages over SSH heard nothing from StorageForge'
    check('scanner-off-sends-nothing', server.name, off_means_off)

    def scanner():
        rng = '10.77.0.32/28'         # the machines behind the routers, and none of the lab's host
        res = api.post('/api/netscan/settings', {'enabled': True, 'ranges': [rng]})
        want(res['enabled'] and res['nmap'], f'{res}: is nmap in the image?')
        node = capture(90)
        started = api.post('/api/netscan/run', {})
        until = time.time() + 180
        while time.time() < until:
            data = api.get(f'/api/netscan?scan={started["scan_id"]}')
            if data['results']['scan'] and data['results']['scan']['status'] != 'running':
                break
            time.sleep(4)
        want(data['results']['scan']['status'] == 'done', data['results']['scan'])
        sudo(node.name, 'pkill tcpdump; sleep 1; true')
        heard = sudo(node.name, 'cat /tmp/cap.txt')
        want(len(heard.splitlines()) > 20, f'nmap ran, and the server heard only {len(heard.splitlines())} packets')
        by = {h['ip']: h for h in data['results']['hosts']}
        for n in (client, server, outside):
            want(n.ip in by, f'{n.ip} was not found: {sorted(by)}')
            want(any(p['port'] == 22 for p in by[n.ip]['ports']), f'{n.ip}: {by[n.ip]["ports"]}')
            want(by[n.ip]['link']['kind'] == 'host' and by[n.ip]['link']['name'] == n.name, by[n.ip]['link'])
            want(any(x['url'] == f'/#host={n.name}&tab=rebuild' for x in by[n.ip]['link']['links']), by[n.ip]['link'])
        return f'{len(by)} machines found, each linked back to its own pages. The server really heard {len(heard.splitlines())} packets'
    check('scanner-finds-and-links', '-', scanner)
    try:
        api.post('/api/netscan/settings', {'enabled': False})
    except Exception:
        pass

    def monitoring():
        api.post('/api/traffic/settings', {'enabled': True})
        api.post('/api/devices/sf-mikrotik/read', {})
        curl(client.name, f'http://{DMZ}/')
        time.sleep(5)
        api.post('/api/devices/sf-mikrotik/read', {})
        time.sleep(1)
        api.post('/api/devices/sf-mikrotik/read', {})
        got = api.get('/api/traffic?host=sf-mikrotik')
        want(got['enabled'], got)
        by = {i['iface']: i for i in got['interfaces']}
        want(by['ether1']['latest'] is not None and by['ether1']['latest']['rx_rate'] > 0, by.get('ether1'))
        api.post('/api/traffic/settings', {'enabled': False})
        return f'{len(by)} interfaces with rates, from the router\'s own counters'
    check('traffic-rates', 'sf-mikrotik', monitoring)

    # ── the management planner ──
    def planner():
        f = api.get('/api/fleet')
        names = {m['name']: m for m in f['machines']}
        want(names['sf-mikrotik']['kind'] == 'device' and names['sf-mikrotik']['nat'] == 2, names['sf-mikrotik'])
        want(names[client.name]['kind'] == 'host', names[client.name])
        want(any(x['to_addr'] == DMZ for x in f['forwards']), f['forwards'])
        page = api.text('/manage')
        want('manage.js' in page and 'Management planner' in page, 'the page itself')
        want('function viewCompose' in api.text('/manage.js'), 'its script')
        wi = api.post('/api/dsl/whatif', {'host': 'sf-mikrotik', 'dsl': '/ip firewall filter add chain=forward protocol=tcp dst-port=9999 action=accept', 'from': LAN, 'to': DMZ, 'port': 80})
        want(wi['before']['verdict'] == wi['after']['verdict'] == 'allowed' and not wi['changed'], wi)
        return f'{len(names)} machines, {len(f["forwards"])} forwards, a what-if from the index'
    check('management-planner', '-', planner)


def quiet_has(vm, tool):
    return subprocess.run([demo.LAB, 'ssh', vm, f'sudo -n sh -c "command -v {tool}"'], capture_output=True, stdin=subprocess.DEVNULL).returncode == 0


def _cut_first(api, router_ssh, ip):
    """RouterOS appends, and a rule below the management accept would change nothing. So this turns the management accept itself to a drop, which is the mistake someone really makes."""
    def fn():
        before = json.loads(router_ssh(ip, ':put [:serialize to=json [/ip/firewall/filter/print as-value]]'))
        rep = api.post('/api/devices/sf-mikrotik/report', {'dsl': '/ip firewall filter add chain=input in-interface=ether1 protocol=tcp dst-port=22 action=drop comment="sf-cut"'})
        want(rep['can_apply'], rep)
        res = api.post(f'/api/devices/changes/{rep["id"]}/apply', {'rollback': 120, 'hold': True})
        want(res['ok'], res)
        # the mistake itself: put it above the accept, which RouterOS's place-before would do. Done from the router's own side, since the language only appends
        router_ssh(ip, ':local a [/ip/firewall/filter/find comment="sf-cut"]; :local b [/ip/firewall/filter/find comment="return-traffic" chain="input"]; /ip/firewall/filter/move $a $b; /ip/firewall/connection/remove [find]')
        time.sleep(10)
        dead = False
        try:
            router_ssh(ip, ':put ok', timeout=8)
        except (RuntimeError, subprocess.TimeoutExpired):
            dead = True
        want(dead, 'the change did not cut SSH off: this proves nothing')
        until = time.time() + 400
        back = False
        while time.time() < until:
            try:
                router_ssh(ip, ':put ok', timeout=8)
                back = True
                break
            except (RuntimeError, subprocess.TimeoutExpired):
                time.sleep(5)
        want(back, 'the router never came back')
        after = json.loads(router_ssh(ip, ':put [:serialize to=json [/ip/firewall/filter/print as-value]]'))
        want([x.get('comment') for x in after] == [x.get('comment') for x in before], 'the rules are not what they were')
        return 'SSH really went dead, the scheduler loaded the backup and rebooted the router, and it came back with the rules it had'
    return fn
