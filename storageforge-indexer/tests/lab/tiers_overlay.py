#!/usr/bin/env python3
"""Tier 22 of the KVM lab: joining and leaving private networks through plan steps, against control servers the lab runs itself
(roadmap section 1.3 and section 2): Headscale with real Tailscale clients, NetBird's own server, a ZeroTier controller, and
Nebula with its CA in the vault.

NOT RUN. This file was written on 2026-11-20 where the KVM lab cannot run, so no check below has ever passed or failed on a real
VM: it is not lab-tested. What was run is tests/test_overlay_steps.py: the steps against stand-ins, and Nebula against the real
nebula-cert and two real nebula nodes in network namespaces. The servers below are set up from each project's own instructions as
read on that day, and a first run will most likely have to correct them before it says anything about StorageForge. A server that
cannot be set up shows as a failed `*-server` check and the checks that need it as skipped, never as passed.

    headscale-server    Headscale from its release package (checked against a pinned hash), listening on the lab network, one user
    headscale-join      `vault headscale-key` makes a pre-auth key on that server over SSH and stores it; `vault send-secret` and
                        the tailscale step, with the server as its control server, join another host. The key is in no argument,
                        plan, script or output, and its file is gone afterwards. Headscale lists the node
    headscale-routes    the joined host advertises a route: the reading of the server shows it waiting, and approved once Headscale
                        approved it
    headscale-leave     the tailscale step with state absent
    netbird-server      NetBird's combined server in Docker, from its own getting-started script (pinned by hash) on the host's
                        address over HTTP, its first account and an API token made through its setup API, and a setup key
    netbird-join        the netbird step joins with the setup key from the vault: read from a file, in no argument, gone afterwards.
                        The server lists the peer
    netbird-leave       state absent: the client is logged out and the server no longer lists the peer
    zerotier-controller ZeroTier on two hosts, and a private network made at the controller that is part of one of them. ZeroTier
                        1.16 and later build no controller by default (it is under another licence): where the package has
                        none, this says so and the ZeroTier checks are skipped
    zerotier-join       the zerotier step joins and says the node waits to be let in; the controller lists it unauthorised; once
                        the lab authorises it there, a second run says it is on the network with an address
    zerotier-leave      state absent
    nebula-join         `vault nebula-ca` and `vault nebula-issue` for a lighthouse and a member; each host's key is a file only
                        root reads that the controller never held; the nebula step writes both configurations; the member reaches
                        the lighthouse over Nebula
    nebula-revoke       the member's certificate revoked, the lighthouse's step run again: the member no longer gets through
    nebula-leave        state absent on both: no unit, no key

Not here: OpenZiti (the lab has no Ziti controller to make an enrollment token) and Netmaker (it has no step, steps_overlay.py
says why). Needs two deployable hosts with systemd, one of them an apt-get host that runs Docker, and the internet for the packages.
The lab logs in as `lab` with sudo; `vault headscale-key`, `vault nebula-issue` and `vault send-secret` use an operator's own SSH
login, so the lab makes a key in the controller's container and lets it in as `lab` on the hosts it uses.
"""
import json
import shlex
import time

import demo
from demo import COMPOSE, ssh

import roles
from tiers_platform import install, quiet, sudo

HEADSCALE = ('0.29.7', 'd230c5fc8db06cf1868f4ec0077b89e5e2ccf3b22a3259efa6d080db2d5f921c')        # headscale_0.29.7_linux_amd64.deb
NETBIRD = ('v0.83.1', '25ee5000a7421cb51a7c4c0f9090788951f531aba171d1fbff676f66d3265bfe')          # getting-started.sh of that release
NEBULA = ('v1.12.0', '44bf6ae565cf7e5391ca49e8c5f9e3b825755c385eacf79a1f0d28a0b7d3fe51')           # nebula-linux-amd64.tar.gz
HS_PORT = 8085
OPERATOR_KEY = '/tmp/sflab-operator'
REACH = ['--user', 'lab', '--key', OPERATOR_KEY, '--ssh-option', 'StrictHostKeyChecking=accept-new', '--ssh-option', 'UserKnownHostsFile=/tmp/sflab-operator-known']


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def in_container(command, stdin=None, check=True):
    return ssh('sf-ctl', f'{COMPOSE} exec -T storageforge {command}', stdin=stdin, check=check)


def vault(*args, stdin=None, check=True):
    return in_container('storageforge-index vault ' + shlex.join(args), stdin=stdin, check=check)


def operator(nodes):
    """An SSH key of the operator's own, in the controller's container, let in as `lab` (which has sudo) on these hosts."""
    make = f"[ -s {OPERATOR_KEY} ] || ssh-keygen -q -t ed25519 -N '' -f {OPERATOR_KEY}; cat {OPERATOR_KEY}.pub"
    public = in_container(f'sh -c {shlex.quote(make)}').strip()
    want(public.startswith('ssh-ed25519 '), f'no operator key was made in the container: {public[:80]}')
    for n in nodes:
        if quiet(n.name, f'grep -qF {shlex.quote(public.split()[1])} ~lab/.ssh/authorized_keys') != 0:
            demo.install_key(n.name, 'lab', public)


def plan(api, title, *tasks):
    """A change plan with these steps, through the whole deploy path. Returns (plan id, the runs of the apply)."""
    pid = api.post('/api/changes', {'name': title, 'tasks': [{'type': kind, 'host': host, 'params': params} for kind, host, params in tasks]})['id']
    return pid, demo.deploy(api, 'changes', pid, title)


def said(runs):
    return '\n'.join(x.get('output') or '' for x in runs or [])


def nowhere(api, node, secret, pid, runs):
    """The secret is in no process's arguments on the host, and in nothing StorageForge kept or showed of the plan."""
    want(secret and len(secret) >= 16, 'the lab has no secret to look for')
    want(secret not in sudo(node.name, 'ps -eo args'), 'the secret is in the arguments of a process on the host')
    for text in (api.text(f'/api/changes/{pid}/script'), json.dumps(api.get(f'/api/changes/{pid}')), json.dumps(runs)):
        want(secret not in text, 'the secret is in a plan, a script or the output of a run')


def overlays_of(host):
    """What the last infrastructure reading of a host says of its private networks, from the controller's own database."""
    code = ("import json, sqlite3; c = sqlite3.connect('/app/data/index.db'); "
            f"r = c.execute(\"SELECT data_json FROM security_measurements WHERE kind = 'infra' AND lower(host) = lower(?)\", ({host!r},)).fetchone(); "
            "print(json.dumps(((json.loads(r[0]) if r else {}).get('access') or {}).get('overlays') or []))")
    return json.loads(in_container(f'python -c {shlex.quote(code)}'))


def tier22(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    hosts = [n for n in roles.deployable() if not n.can('nosystemd')]
    server = next((n for n in hosts if n.pm == 'apt-get' and n.can('docker')), None)
    member = next((n for n in hosts if server and n.name != server.name and n.pm in ('apt-get', 'dnf')), None)
    if not server or not member:
        r.add('overlay', '-', None, 'needs an apt-get host that runs Docker and a second apt-get or dnf host, both taking deploys')
        return
    name = {n.name: demo.known_as(api, n.name) for n in (server, member)}
    for n in (server, member):
        install(n, 'curl')
    operator([server, member])
    up = {}                                               # which servers came up: the checks that need one are skipped without it

    def needs(what, check, node, fn):
        if up.get(what):
            r.check(check, node.name, fn)
        else:
            r.add(check, node.name, None, f'skipped: the {what} server of this lab is not up')

    # ── Headscale, with real Tailscale clients ──
    def headscale_server():
        version, sha = HEADSCALE
        sudo(server.name, f'cd /tmp && curl -fsSL --retry 3 -o headscale.deb https://github.com/juanfont/headscale/releases/download/v{version}/headscale_{version}_linux_amd64.deb '
                          f'&& echo "{sha}  headscale.deb" | sha256sum -c - >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y ./headscale.deb')
        sudo(server.name, f"sed -i -e 's#^server_url:.*#server_url: http://{server.ip}:{HS_PORT}#' -e 's#^listen_addr:.*#listen_addr: 0.0.0.0:{HS_PORT}#' /etc/headscale/config.yaml "
                          '&& systemctl enable --now headscale && systemctl restart headscale')
        want(quiet(server.name, f'for i in $(seq 1 20); do curl -fsS -o /dev/null http://127.0.0.1:{HS_PORT}/health && exit 0; sleep 2; done; exit 1') == 0, 'Headscale does not answer on its port')
        sudo(server.name, 'headscale users list -o json | grep -q \'"name": *"lab"\' || headscale users create lab')
        users = json.loads(sudo(server.name, 'headscale users list -o json'))
        up['Headscale'] = str(next(u['id'] for u in users if u.get('name') == 'lab'))
        return f'Headscale {version} from its release package, listening on {server.ip}:{HS_PORT}, with the user lab (number {up["Headscale"]})'
    r.check('headscale-server', server.name, headscale_server)

    def headscale_join():
        out = vault('headscale-key', 'lab-hs-key', '--host', server.ip, '--hs-user', up['Headscale'], '--reusable', '--expiration', '2h', *REACH)
        want('stored secret lab-hs-key' in out and 'hskey-' not in out, f'the key was not stored, or it was printed: {out[:200]}')
        vault('send-secret', 'lab-hs-key', '--host', member.ip, *REACH)
        key = sudo(member.name, 'cat /run/storageforge/secrets/lab-hs-key').strip()          # the lab may look: it is how it knows what to search for
        want(sudo(member.name, 'stat -c "%a %U" /run/storageforge/secrets/lab-hs-key').strip() == '600 root', 'the key file on the host is not root-only')
        pid, runs = plan(api, f'lab: {member.name} joins Headscale', ('tailscale', name[member.name], {'secret': 'lab-hs-key', 'login_server': f'http://{server.ip}:{HS_PORT}', 'hostname': 'sflab-member'}))
        want('joined the tailnet' in said(runs), f'the step did not say it joined: {said(runs)[-600:]}')
        want('"BackendState": "Running"' in sudo(member.name, 'tailscale status --json'), 'tailscale on the host is not running')
        want(quiet(member.name, 'test -e /run/storageforge/secrets/lab-hs-key') != 0, 'the key file was not removed after joining')
        nowhere(api, member, key, pid, runs)
        nodes = json.loads(sudo(server.name, 'headscale nodes list -o json'))
        want(any((n.get('given_name') or n.get('givenName')) == 'sflab-member' for n in nodes), f'Headscale does not list the node: {[n.get("given_name") for n in nodes]}')
        _, again = plan(api, f'lab: {member.name} joins Headscale again', ('tailscale', name[member.name], {'secret': 'lab-hs-key', 'login_server': f'http://{server.ip}:{HS_PORT}'}))
        want('on a tailnet already' in said(again), 'a second run did not find it joined')
        return 'a pre-auth key made on the Headscale server went into the vault, to the host on stdin and into tailscale as a file; Headscale lists the node; the key was in no argument, plan, script or output'
    needs('Headscale', 'headscale-join', member, headscale_join)

    def headscale_routes():
        sudo(member.name, 'tailscale set --advertise-routes=192.168.77.0/24')
        time.sleep(5)
        api.post('/api/infra/measure', {'host': name[server.name]})
        read = next((o for o in overlays_of(name[server.name]) if o.get('control') == 'headscale'), None)
        want(read, 'the reading of the server has no Headscale in it')
        node = next((p for p in read['peers'] if p['name'] == 'sflab-member'), None)
        want(node and node.get('routes_waiting') == ['192.168.77.0/24'] and not node['routes'], f'an advertised route is not shown as waiting: {node}')
        ident = next(n['id'] for n in json.loads(sudo(server.name, 'headscale nodes list -o json')) if (n.get('given_name') or n.get('givenName')) == 'sflab-member')
        sudo(server.name, f'headscale nodes approve-routes --identifier {ident} --routes 192.168.77.0/24')
        api.post('/api/infra/measure', {'host': name[server.name]})
        node = next(p for p in next(o for o in overlays_of(name[server.name]) if o.get('control') == 'headscale')['peers'] if p['name'] == 'sflab-member')
        want(node['routes'] == ['192.168.77.0/24'] and not node['routes_waiting'], f'an approved route is not shown as approved: {node}')
        return 'a route the node advertised was read as waiting, and as approved once Headscale approved it'
    needs('Headscale', 'headscale-routes', server, headscale_routes)

    def headscale_leave():
        _, runs = plan(api, f'lab: {member.name} leaves Headscale', ('tailscale', name[member.name], {'secret': 'lab-hs-key', 'state': 'absent'}))
        want('left the tailnet' in said(runs), f'the step did not say it left: {said(runs)[-400:]}')
        want('"BackendState": "Running"' not in sudo(member.name, 'tailscale status --json 2>/dev/null; true', check=False), 'tailscale is still running on the host')
        _, again = plan(api, f'lab: {member.name} leaves Headscale again', ('tailscale', name[member.name], {'secret': 'lab-hs-key', 'state': 'absent'}))
        want('not on a tailnet' in said(again), 'a second run did not find it gone')
        sudo(member.name, 'systemctl disable --now tailscaled >/dev/null 2>&1; true', check=False)       # NetBird hands out the same range next
        return 'tailscale logged out, and a second run changed nothing'
    needs('Headscale', 'headscale-leave', member, headscale_leave)

    # ── NetBird, with its own server ──
    def netbird_server():
        version, sha = NETBIRD
        install(server, 'jq')
        compose_extra = 'services:\n  netbird-server:\n    ports:\n      - "80:80"\n    environment:\n      - NB_SETUP_PAT_ENABLED=true\n'
        sudo(server.name, 'mkdir -p /opt/sflab-netbird && cat >/opt/sflab-netbird/docker-compose.override.yml', stdin=compose_extra)
        sudo(server.name, f'cd /opt/sflab-netbird && [ -f config.yaml ] || {{ curl -fsSL --retry 3 -o getting-started.sh https://github.com/netbirdio/netbird/releases/download/{version}/getting-started.sh '
                          f'&& echo "{sha}  getting-started.sh" | sha256sum -c - >/dev/null '
                          '&& NETBIRD_DOMAIN=use-ip NETBIRD_REVERSE_PROXY_TYPE=5 NETBIRD_NON_INTERACTIVE=true bash getting-started.sh >install.log 2>&1; }')
        url = f'http://{server.ip}'
        want(quiet(server.name, f'for i in $(seq 1 60); do curl -fsS -o /dev/null {url}/oauth2/.well-known/openid-configuration && exit 0; sleep 2; done; exit 1') == 0,
             'NetBird does not answer on port 80 of the host: /opt/sflab-netbird/install.log and docker compose logs say why')
        body = json.dumps({'email': 'lab@sflab.invalid', 'name': 'Lab', 'password': 'sflab-' + sha[:24], 'create_pat': True, 'pat_expire_in': 1})
        made = json.loads(sudo(server.name, f'curl -fsS -X POST {url}/api/setup -H "Content-Type: application/json" -d @-', stdin=body))
        pat = made.get('personal_access_token')
        want(pat, f'the setup API gave no token (it does so once, while there is no account): {list(made)}')
        key = json.loads(sudo(server.name, f'curl -fsS -X POST {url}/api/setup-keys -H "Authorization: Token {pat}" -H "Content-Type: application/json" -d @-',
                              stdin=json.dumps({'name': 'sflab', 'type': 'reusable', 'expires_in': 86400, 'usage_limit': 0, 'auto_groups': []})))
        want(key.get('key'), f'no setup key was made: {list(key)}')
        vault('secret-add', 'lab-nb-key', stdin=key['key'] + '\n')
        up['NetBird'] = {'url': url, 'pat': pat, 'key': key['key']}
        return f'NetBird {version} in Docker on {url} (HTTP, its own address), with an account, an API token and a setup key made through its API'
    r.check('netbird-server', server.name, netbird_server)

    def netbird_peers():
        nb = up['NetBird']
        return json.loads(sudo(server.name, f'curl -fsS {nb["url"]}/api/peers -H "Authorization: Token {nb["pat"]}"'))

    def netbird_join():
        nb = up['NetBird']
        sudo(member.name, 'command -v netbird >/dev/null || { curl -fsSL --retry 3 -o /tmp/netbird-install.sh https://pkgs.netbird.io/install.sh && sh /tmp/netbird-install.sh; }')
        vault('send-secret', 'lab-nb-key', '--host', member.ip, *REACH)
        pid, runs = plan(api, f'lab: {member.name} joins NetBird', ('netbird', name[member.name], {'secret': 'lab-nb-key', 'management_url': nb['url'], 'hostname': 'sflab-member'}))
        want('joined the NetBird network' in said(runs), f'the step did not say it joined: {said(runs)[-600:]}')
        status = json.loads(sudo(member.name, 'netbird status --json'))
        want(status['management']['connected'] is True, f'netbird on the host is not connected to its management server: {status["management"]}')
        want(quiet(member.name, 'test -e /run/storageforge/secrets/lab-nb-key') != 0, 'the setup key file was not removed after joining')
        nowhere(api, member, nb['key'], pid, runs)
        want(any('sflab-member' in (p.get('hostname') or '') + (p.get('name') or '') for p in netbird_peers()), 'the NetBird server does not list the peer')
        _, again = plan(api, f'lab: {member.name} joins NetBird again', ('netbird', name[member.name], {'secret': 'lab-nb-key', 'management_url': nb['url']}))
        want('on a NetBird network already' in said(again), 'a second run did not find it joined')
        api.post('/api/infra/measure', {'host': name[member.name]})
        want(any(o.get('network') == 'netbird' and o.get('state') == 'connected' for o in overlays_of(name[member.name])), 'the reading of the host does not show NetBird connected')
        return 'the setup key was read from a file by the real netbird, which joined the lab server; the key was in no argument, plan, script or output'
    needs('NetBird', 'netbird-join', member, netbird_join)

    def netbird_leave():
        _, runs = plan(api, f'lab: {member.name} leaves NetBird', ('netbird', name[member.name], {'secret': 'lab-nb-key', 'state': 'absent'}))
        want('left the NetBird network' in said(runs), f'the step did not say it left: {said(runs)[-400:]}')
        want('NeedsLogin' in sudo(member.name, 'netbird status 2>&1; true', check=False), 'netbird on the host is still logged in')
        want(not any('sflab-member' in (p.get('hostname') or '') + (p.get('name') or '') for p in netbird_peers()), 'the NetBird server still lists the peer')
        _, again = plan(api, f'lab: {member.name} leaves NetBird again', ('netbird', name[member.name], {'secret': 'lab-nb-key', 'state': 'absent'}))
        want('not registered' in said(again), 'a second run did not find it gone')
        return 'netbird deregistered: the client is logged out and the server no longer lists the peer'
    needs('NetBird', 'netbird-leave', member, netbird_leave)

    # ── ZeroTier, with the controller that is part of the service where the package has one ──
    def zt_api(method, path, body=None):
        data = f"-d {shlex.quote(json.dumps(body))}" if body is not None else ''
        return sudo(server.name, f'curl -fsS -X {method} -H "X-ZT1-Auth: $(cat /var/lib/zerotier-one/authtoken.secret)" {data} http://127.0.0.1:9993{path}')

    def zerotier_controller():
        for n in (server, member):
            sudo(n.name, 'command -v zerotier-cli >/dev/null || { curl -fsSL --retry 3 -o /tmp/zerotier-install.sh https://install.zerotier.com && bash /tmp/zerotier-install.sh; }')
        sudo(member.name, 'systemctl stop zerotier-one')           # the step is the one that starts it
        node = sudo(server.name, 'zerotier-cli info').split()[2]
        if quiet(server.name, 'curl -fsS -o /dev/null -H "X-ZT1-Auth: $(cat /var/lib/zerotier-one/authtoken.secret)" http://127.0.0.1:9993/controller') != 0:
            raise AssertionError(f'this ZeroTier ({sudo(server.name, "zerotier-cli -v").strip()}) has no controller in it: since 1.16 the controller is built only with ZT_NONFREE=1, '
                                 'under a licence of its own. The lab needs a build that has one, which is the owner\'s decision')
        made = json.loads(zt_api('POST', f'/controller/network/{node}______', {'name': 'sflab', 'private': True, 'v4AssignMode': {'zt': True},
                                                                               'ipAssignmentPools': [{'ipRangeStart': '10.98.0.10', 'ipRangeEnd': '10.98.0.250'}], 'routes': [{'target': '10.98.0.0/24'}]}))
        up['ZeroTier'] = made.get('nwid') or made['id']
        return f'a private ZeroTier network {up["ZeroTier"]} at the controller on {server.name}'
    r.check('zerotier-controller', server.name, zerotier_controller)

    def zerotier_join():
        net = up['ZeroTier']
        _, runs = plan(api, f'lab: {member.name} joins ZeroTier', ('zerotier', name[member.name], {'network': net}))
        want(f'asked to join {net}' in said(runs), f'the step did not say it asked to join: {said(runs)[-600:]}')
        node = sudo(member.name, 'zerotier-cli info').split()[2]
        want(node in said(runs), 'the step did not name the node to authorise')
        listed = json.loads(zt_api('GET', f'/controller/network/{net}/member/{node}'))
        want(listed.get('authorized') is False, f'the controller does not list the node as waiting: {listed}')
        zt_api('POST', f'/controller/network/{net}/member/{node}', {'authorized': True})
        want(quiet(member.name, f'for i in $(seq 1 30); do [ "$(zerotier-cli get {net} status)" = OK ] && exit 0; sleep 2; done; exit 1') == 0, 'the node was authorised and never came up')
        _, again = plan(api, f'lab: {member.name} joins ZeroTier again', ('zerotier', name[member.name], {'network': net}))
        want(f'on ZeroTier network {net} as 10.98.0.' in said(again), f'a second run did not find it on the network: {said(again)[-400:]}')
        return 'the step joined and said which node waits; the controller listed it unauthorised; once authorised there, a second run found it on the network with an address'
    needs('ZeroTier', 'zerotier-join', member, zerotier_join)

    def zerotier_leave():
        net = up['ZeroTier']
        _, runs = plan(api, f'lab: {member.name} leaves ZeroTier', ('zerotier', name[member.name], {'network': net, 'state': 'absent'}))
        want(f'left ZeroTier network {net}' in said(runs), f'the step did not say it left: {said(runs)[-400:]}')
        want(net not in sudo(member.name, 'zerotier-cli listnetworks'), 'the host still lists the network')
        _, again = plan(api, f'lab: {member.name} leaves ZeroTier again', ('zerotier', name[member.name], {'network': net, 'state': 'absent'}))
        want(f'not on ZeroTier network {net}' in said(again), 'a second run did not find it gone')
        return 'zerotier-cli left the network, and a second run changed nothing'
    needs('ZeroTier', 'zerotier-leave', member, zerotier_leave)

    # ── Nebula: no server but a lighthouse, and a CA whose key is in the vault ──
    light, short = '10.99.0.1', {n.name: name[n.name].split('.')[0].lower() for n in (server, member)}
    lighthouses = f'{light}={server.ip}:4242'

    def nebula_join():
        version, sha = NEBULA
        for n in (server, member):
            sudo(n.name, f'command -v nebula >/dev/null || {{ cd /tmp && curl -fsSL --retry 3 -o nebula.tar.gz https://github.com/slackhq/nebula/releases/download/{version}/nebula-linux-amd64.tar.gz '
                         f'&& echo "{sha}  nebula.tar.gz" | sha256sum -c - >/dev/null && tar -xzf nebula.tar.gz -C /usr/local/bin nebula nebula-cert; }}')
        ca = vault('nebula-ca', 'sflab', '--networks', '10.99.0.0/24', check=False)
        want('BEGIN NEBULA CERTIFICATE' in ca or 'already' in vault('nebula-list'), 'no Nebula CA was made')
        for n, address in ((server, f'{light}/24'), (member, '10.99.0.5/24')):
            out = vault('nebula-issue', 'sflab', '--host', n.ip, '--address', address, '--name', short[n.name], *REACH)
            want('Its key was made on the host and stays there' in out, f'no certificate was issued for {n.name}: {out[:300]}')
            want(sudo(n.name, 'stat -c "%a %U" /etc/nebula/host.key').strip() == '600 root', f'the Nebula key on {n.name} is not root-only')
            want(quiet(n.name, 'nebula-cert verify -ca /etc/nebula/ca.crt -crt /etc/nebula/host.crt') == 0, f'nebula-cert on {n.name} does not accept the certificate')
        key_line = sudo(member.name, 'sed -n 2p /etc/nebula/host.key').strip()
        pid, runs = plan(api, 'lab: a Nebula network of two',
                         ('nebula', name[server.name], {'ca': 'sflab', 'lighthouse': True, 'lighthouses': lighthouses, 'inbound': 'icmp'}),
                         ('nebula', name[member.name], {'ca': 'sflab', 'lighthouses': lighthouses, 'inbound': 'icmp'}))
        want(said(runs).count('Nebula runs as storageforge-nebula.service') == 2, f'the step did not start Nebula on both: {said(runs)[-800:]}')
        nowhere(api, member, key_line, pid, runs)
        dump = in_container("python -c \"import sqlite3; print(' '.join(str(r) for r in sqlite3.connect('/app/data/index.db').execute('SELECT value_json FROM settings')))\"")
        want(key_line not in dump and 'PRIVATE KEY' not in dump, 'a Nebula private key is in the controller\'s settings')
        want(quiet(member.name, f'for i in 1 2 3 4 5; do ping -c 1 -W 2 {light} >/dev/null 2>&1 && exit 0; sleep 2; done; exit 1') == 0, 'the member does not reach the lighthouse over Nebula')
        _, again = plan(api, 'lab: the Nebula network again', ('nebula', name[member.name], {'ca': 'sflab', 'lighthouses': lighthouses, 'inbound': 'icmp'}))
        want('doing:' not in said(again) and 'Nebula runs as' in said(again), 'a second run changed something')
        up['Nebula'] = True
        return 'a CA in the vault issued certificates for keys the two hosts made; the step wrote both configurations; the member reached the lighthouse over Nebula; no private key left a host'
    r.check('nebula-join', member.name, nebula_join)

    def nebula_revoke():
        vault('nebula-revoke', 'sflab', short[member.name])
        _, runs = plan(api, 'lab: the lighthouse learns of a revoked certificate', ('nebula', name[server.name], {'ca': 'sflab', 'lighthouse': True, 'lighthouses': lighthouses, 'inbound': 'icmp'}))
        want('blocklist' in sudo(server.name, 'cat /etc/nebula/config.yml'), f'the lighthouse has no blocklist after the step: {said(runs)[-400:]}')
        sudo(member.name, 'systemctl restart storageforge-nebula')          # a tunnel that is up stays up: a new handshake is what gets refused
        time.sleep(5)
        want(quiet(member.name, f'ping -c 2 -W 2 {light} >/dev/null 2>&1') != 0, 'the member still reaches the lighthouse with a revoked certificate')
        return 'the revoked certificate reached the lighthouse through its step, and the member no longer got through'
    needs('Nebula', 'nebula-revoke', server, nebula_revoke)

    def nebula_leave():
        _, runs = plan(api, 'lab: both leave Nebula', ('nebula', name[server.name], {'ca': 'sflab', 'state': 'absent'}), ('nebula', name[member.name], {'ca': 'sflab', 'state': 'absent'}))
        want(said(runs).count('Nebula no longer runs from here') == 2, f'the step did not stop Nebula on both: {said(runs)[-600:]}')
        for n in (server, member):
            want(sudo(n.name, 'ls /etc/nebula/host.key /etc/systemd/system/storageforge-nebula.service 2>/dev/null; true', check=False).strip() == '', f'{n.name} still has the key or the unit')
            want(quiet(n.name, 'ip link show nebula1') != 0, f'{n.name} still has the Nebula interface')
        return 'the unit, the configuration and the host key are gone from both'
    needs('Nebula', 'nebula-leave', member, nebula_leave)
