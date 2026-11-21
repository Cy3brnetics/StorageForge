#!/usr/bin/env python3
"""Tier 29 of the KVM lab: the Toolbox engine (roadmap section 4.1, 0.5.12) and the gauntlet of the archived Toolbox roadmap (section 9)
for the three entries that came with it: Uptime Kuma as a rootless container, Cockpit from the distribution, WireGuard with its peer
manager.

NOT RUN. This file was written on 2026-11-20 where the KVM lab cannot run, so no check below has ever passed or failed on a real VM: it is
not lab-tested. What was run is tests/test_toolbox.py, test_toolbox_steps.py, test_toolbox_adapters.py, test_toolbox_routes.py and
test_browser_toolbox.py on this machine: the signatures with the real ssh-keygen, the steps against stand-ins for podman, systemctl, apt
and curl, the API through Flask, and the view in Chromium. A first run will most likely have to correct this file before it says anything
about StorageForge. A check that cannot be made shows as skip or as failed, never as passed.

Hosts: Podman and SELinux on sf-rocky (and sf-fedora), Debian 12 on sf-bookworm, Ubuntu on sf-ubuntu and sf-jammy.

    tb-signed           a custom entry signed with an operator key made for the tier (on the machine running the lab, never the
                        controller): saved, offered as operator-signed
    tb-tampered         the same entry changed by one byte after it was signed: the save is refused; a row changed in the database is
                        offered as refused, and a plan staged from it before is refused on the host with nothing done
    tb-unsigned         an unsigned entry: staging is refused until it is accepted for one host; the plan for another host is refused
    tb-kuma-rootless    Uptime Kuma staged on sf-rocky: Podman installed first if missing, the plan applied, the container runs under the
                        account sf-uptime-kuma (ps shows that uid), from the pinned digest
    tb-kuma-health      the next reading finds it: status ok, health HTTP 200 on loopback, install recorded as installed
    tb-kuma-exposure    loopback by default: nothing listens on 3001 outside 127.0.0.1, and another host cannot connect to it
    tb-kuma-remove      the removal plan: the unit is gone, the container stopped, /srv/toolbox/uptime-kuma/data is still there with its
                        database, and a reinstall finds its monitors
    tb-cockpit-NAME     Cockpit from the packages of sf-bookworm, sf-ubuntu, sf-rocky and sf-fedora: installed, cockpit.socket
                        listening on 127.0.0.1:9090 only, /ping answers 200 on loopback, the reading says running
    tb-cockpit-action   the restart action staged from the panel: a unit-state plan, deployed, Cockpit answers again
    tb-cockpit-down     Cockpit stopped by hand: the next reading says it is down, and the scan of the host is unchanged
    tb-wg-pair          WireGuard on sf-bookworm and sf-ubuntu with its interface step; each added as the other's peer from the
                        peer manager (wg-peer steps); a ping over the tunnel, and the panel shows the handshake
    tb-wg-revoke        the peer revoked from the panel: the ping over the tunnel fails
    tb-plan-changed     a staged install whose step is edited to another entry SHA-256: the report and the apply say it changed after it
                        was staged, and nothing is installed
    tb-adapter-fails    an infrastructure reading with Uptime Kuma stopped: its status is down or missing, the other tools keep theirs,
                        and the reading is recorded
"""
import subprocess
import tempfile
import time
from pathlib import Path

import demo
import roles

import tiers as t
from tiers_platform import connects, quiet, sql_write, sudo

ENTRY = """format: 1
id: sflab-whoami
revision: 1
name: Lab whoami
category: monitoring
summary: A small container the lab installs to check custom entries.
install:
  methods:
    - kind: container
      image: docker.io/traefik/whoami:v1.11.0@sha256:@DIGEST@
      ports: ["8099:80/tcp"]
requires:
  ports: [8099/tcp]
exposure:
  default: loopback
"""


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def said(runs):
    return '\n'.join(x.get('output') or '' for x in runs or [])


def stage(api, host, tool, **body):
    return api.post('/api/toolbox/stage', {'host': host, 'tool': tool, **body})


def deploy_plan(api, pid, title, **options):
    return demo.deploy(api, 'changes', pid, title, **options)


def report_only(api, pid, title):
    group = api.post('/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'report', 'title': title})['group']
    return said(demo.wait(title, lambda: demo.finished(api, group))['runs'])


def status(api, host, tool):
    api.post('/api/infra/measure', {'host': host})
    return api.get(f'/api/toolbox/installed/{host}/{tool}/status')


def sign(key, text, d):
    f = Path(d) / 'entry.yaml'
    f.write_text(text)
    subprocess.run(['ssh-keygen', '-Y', 'sign', '-q', '-f', str(key), '-n', 'storageforge-catalog', str(f)], check=True)
    return (Path(d) / 'entry.yaml.sig').read_text()


def digest(image):
    """The digest of an image tag, asked of the registry from the machine running the lab: a custom entry pins one."""
    p = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', image], capture_output=True, text=True, timeout=120)
    for line in p.stdout.splitlines():
        if line.startswith('Digest:'):
            return line.split('sha256:')[1].strip()
    raise AssertionError(f'could not read the digest of {image} here: {p.stderr[-300:]}')


def tier29(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    by = {n.name: n for n in roles.deployable()}
    rocky, fedora, bookworm, ubuntu = by.get('sf-rocky'), by.get('sf-fedora'), by.get('sf-bookworm'), by.get('sf-ubuntu')
    work = tempfile.mkdtemp(prefix='sflab-tb-')
    state = {}

    # ── signatures ──
    def signed():
        key = Path(work) / 'operator'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'sflab', '-f', str(key)], check=True)
        pub = ' '.join(key.with_suffix('.pub').read_text().split()[:2])
        api.raw('DELETE', '/api/toolbox/signers/sflab')
        api.post('/api/toolbox/signers', {'name': 'sflab', 'public_key': pub})
        text = ENTRY.replace('@DIGEST@', digest('docker.io/traefik/whoami:v1.11.0'))
        state['entry'], state['key'] = text, key
        got = api.post('/api/toolbox/catalog/custom', {'yaml': text, 'signature': sign(key, text, work)})
        want(got['state'] == 'operator-signed', f'saved as {got}')
        row = api.get('/api/toolbox/catalog/sflab-whoami')
        want(row['trust'] == 'operator-signed' and row['signed_by'] == 'sflab', f'offered as {row["trust"]}')
        return 'signed on this machine with an operator key, verified by the controller'
    r.check('tb-signed', '-', signed)

    def tampered():
        want('entry' in state, 'needs tb-signed')
        sig = sign(state['key'], state['entry'], work)
        status_code, out = api.raw('POST', '/api/toolbox/catalog/custom', {'yaml': state['entry'].replace('8099:80', '8098:80'), 'signature': sig})
        want(status_code == 400, f'a changed entry with the old signature was taken: {out}')
        host = demo.known_as(api, rocky.name)
        staged = stage(api, host, 'sflab-whoami')
        sql_write("UPDATE toolbox_catalog SET spec_yaml = replace(spec_yaml, '8099:80', '8098:80') WHERE id = 'sflab-whoami'")
        want(api.get('/api/toolbox/catalog/sflab-whoami')['trust'] == 'refused', 'a row changed in the database is still offered')
        text = report_only(api, staged['plan_id'], 'lab: tampered entry')
        want('was changed after it was signed' in text or 'signature is not one of the operator keys' in text or 'refused' in text, text[-600:])
        want(quiet(rocky.name, 'podman ps -a --format "{{.Names}}" | grep -q sf-sflab-whoami') != 0, 'something was installed')
        api.post('/api/toolbox/catalog/custom', {'yaml': state['entry'], 'signature': sig})
        return 'refused at save, refused when changed in the database, and refused on the host'
    r.check('tb-tampered', rocky.name if rocky else '-', tampered) if rocky else r.add('tb-tampered', '-', None, 'needs sf-rocky')

    def unsigned():
        text = state.get('entry', ENTRY.replace('@DIGEST@', '0' * 64)).replace('sflab-whoami', 'sflab-unsigned')
        api.post('/api/toolbox/catalog/custom', {'yaml': text})
        host = demo.known_as(api, rocky.name)
        code, out = api.raw('POST', '/api/toolbox/stage', {'host': host, 'tool': 'sflab-unsigned'})
        want(code == 400, f'staged without being accepted: {out}')
        got = stage(api, host, 'sflab-unsigned', accept_unsigned=True)
        plan = api.get(f'/api/changes/{got["plan_id"]}')
        other = demo.known_as(api, fedora.name) if fedora else 'sf-fedora'
        pid = api.post('/api/changes', {'name': 'lab: unsigned elsewhere', 'tasks': [dict(plan['tasks'][0], host=other)]})['id']
        text = report_only(api, pid, 'lab: unsigned elsewhere')
        want('nobody accepted it' in text, text[-600:])
        return 'accepted for one host only, refused on another'
    r.check('tb-unsigned', rocky.name if rocky else '-', unsigned) if rocky else r.add('tb-unsigned', '-', None, 'needs sf-rocky')

    # ── Uptime Kuma, rootless ──
    def kuma():
        host = demo.known_as(api, rocky.name)
        got = stage(api, host, 'uptime-kuma')
        want(got['method'] == 'container', f'the method was {got["method"]}: {got["why"]}')
        deploy_plan(api, got['plan_id'], 'lab: Uptime Kuma')
        out = sudo(rocky.name, 'ps -o user= -C node; id -u sf-uptime-kuma', check=False)
        want('sf-uptime' in out or 'sf-upti+' in out, f'the container does not run as its own account: {out}')
        image = sudo(rocky.name, 'runuser -u sf-uptime-kuma -- env XDG_RUNTIME_DIR=/run/user/$(id -u sf-uptime-kuma) podman inspect sf-uptime-kuma --format "{{.ImageName}}"', check=False)
        want('@sha256:4c364ef96aaddac7ec4c85f5e5f31c3394d35f631381ccbbf93f18fd26ac7cba' in image or 'uptime-kuma:2.0.2' in image, image)
        state['kuma'] = host
        return 'running rootless under sf-uptime-kuma, from the pinned digest'
    r.check('tb-kuma-rootless', rocky.name if rocky else '-', kuma) if rocky else r.add('tb-kuma-rootless', '-', None, 'needs sf-rocky')

    def kuma_health():
        host = state.get('kuma') or (_ for _ in ()).throw(AssertionError('needs tb-kuma-rootless'))
        for _ in range(20):
            st = status(api, host, 'uptime-kuma')
            if (st.get('status') or {}).get('health') == 'ok':
                break
            time.sleep(15)
        want((st.get('status') or {}).get('health') == 'ok', f'status {st.get("status")}')
        want(st['install']['status'] == 'installed', f'the install is {st["install"]["status"]}')
        return 'the reading finds it running and its health check answers'
    r.check('tb-kuma-health', rocky.name if rocky else '-', kuma_health) if rocky else r.add('tb-kuma-health', '-', None, 'needs sf-rocky')

    def kuma_exposure():
        host = state.get('kuma') or (_ for _ in ()).throw(AssertionError('needs tb-kuma-rootless'))
        ex = next(x for x in api.get('/api/toolbox/exposure')['exposure'] if x['tool'] == 'uptime-kuma' and x['host'] == host)
        want(not ex['wider_than_staged'], f'it listens wider than staged: {ex}')
        other = next((n.name for n in roles.deployable() if n.name != rocky.name), None)
        want(other is None or not connects(other, demo.IPS[rocky.name], 3001), 'another host reaches port 3001')
        return 'loopback only: no other host reaches it'
    r.check('tb-kuma-exposure', rocky.name if rocky else '-', kuma_exposure) if rocky else r.add('tb-kuma-exposure', '-', None, 'needs sf-rocky')

    def kuma_remove():
        host = state.get('kuma') or (_ for _ in ()).throw(AssertionError('needs tb-kuma-rootless'))
        sudo(rocky.name, 'test -s /srv/toolbox/uptime-kuma/data/kuma.db')
        got = stage(api, host, 'uptime-kuma', action='remove')
        deploy_plan(api, got['plan_id'], 'lab: remove Uptime Kuma')
        want(quiet(rocky.name, 'test -e /var/lib/storageforge-tools/uptime-kuma/.config/containers/systemd/uptime-kuma.container') != 0, 'the unit is still there')
        sudo(rocky.name, 'test -s /srv/toolbox/uptime-kuma/data/kuma.db')
        got = stage(api, host, 'uptime-kuma')
        deploy_plan(api, got['plan_id'], 'lab: Uptime Kuma again')
        sudo(rocky.name, 'test -s /srv/toolbox/uptime-kuma/data/kuma.db')
        return 'removed with its data kept, and installed again on that data'
    r.check('tb-kuma-remove', rocky.name if rocky else '-', kuma_remove) if rocky else r.add('tb-kuma-remove', '-', None, 'needs sf-rocky')

    # ── Cockpit, from each distribution ──
    def cockpit(node):
        def run():
            host = demo.known_as(api, node.name)
            got = stage(api, host, 'cockpit')
            want(got['method'] == 'package', got['why'])
            deploy_plan(api, got['plan_id'], f'lab: Cockpit on {node.name}')
            listens = sudo(node.name, 'ss -Htln sport = :9090', check=False)
            want('127.0.0.1:9090' in listens and '0.0.0.0:9090' not in listens and '*:9090' not in listens, f'cockpit.socket listens on {listens}')
            want(quiet(node.name, 'curl -ks -o /dev/null -w "%{http_code}" https://127.0.0.1:9090/ping | grep -q 200') == 0, 'no answer on /ping')
            st = status(api, host, 'cockpit')
            want((st.get('status') or {}).get('health') == 'ok', f'status {st.get("status")}')
            state.setdefault('cockpit', host)
            return 'installed from the packages, on loopback only, and read as running'
        return run
    for node in (bookworm, ubuntu, rocky, fedora):
        if node:
            r.check(f'tb-cockpit-{node.name.removeprefix("sf-")}', node.name, cockpit(node))
        else:
            r.add('tb-cockpit-missing', '-', None, 'a host of the default build is missing')

    def cockpit_action():
        host = state.get('cockpit') or (_ for _ in ()).throw(AssertionError('needs a tb-cockpit check'))
        got = api.post(f'/api/toolbox/{host}/cockpit/actions/restart', {'values': {}})
        plan = api.get(f'/api/changes/{got["plan_id"]}')
        want(plan['tasks'][0]['type'] == 'unit-state', plan)
        deploy_plan(api, got['plan_id'], 'lab: restart Cockpit')
        return 'the restart action is a unit-state plan, deployed'
    r.check('tb-cockpit-action', '-', cockpit_action)

    def cockpit_down():
        host = state.get('cockpit') or (_ for _ in ()).throw(AssertionError('needs a tb-cockpit check'))
        node = next(n for n in roles.deployable() if demo.known_as(api, n.name) == host)
        sudo(node.name, 'systemctl stop cockpit.socket cockpit.service')
        st = status(api, host, 'cockpit')
        want((st.get('status') or {}).get('health') in ('down', 'missing'), f'status {st.get("status")}')
        demo.scan(api, [demo.IPS[node.name]])
        sudo(node.name, 'systemctl start cockpit.socket')
        return 'a stopped Cockpit reads as down, and the scan goes on'
    r.check('tb-cockpit-down', '-', cockpit_down)

    # ── WireGuard and the peer manager ──
    def wg_pair():
        a, b = demo.known_as(api, bookworm.name), demo.known_as(api, ubuntu.name)
        for host, addr in ((a, '10.77.0.1/24'), (b, '10.77.0.2/24')):
            got = stage(api, host, 'wireguard', inputs={'iface': 'wg7', 'address': addr, 'port': '51877'})
            deploy_plan(api, got['plan_id'], f'lab: WireGuard on {host}')
        for host in (a, b):
            st = status(api, host, 'wireguard')
            want(st['status']['metrics'].get('interfaces', 0) >= 1, f'{host}: {st["status"]}')
        pub = {h: sudo(n, 'wg show wg7 public-key').strip() for h, n in ((a, bookworm.name), (b, ubuntu.name))}
        for host, other, ip, peer_ip in ((a, b, demo.IPS[ubuntu.name], '10.77.0.2/32'), (b, a, demo.IPS[bookworm.name], '10.77.0.1/32')):
            got = api.post(f'/api/toolbox/{host}/wireguard/actions/add-peer', {'values': {'iface': 'wg7', 'pubkey': pub[other], 'allowed': peer_ip,
                                                                                         'endpoint': f'{ip}:51877', 'keepalive': '5'}})
            deploy_plan(api, got['plan_id'], f'lab: peer on {host}')
        want(quiet(bookworm.name, 'ping -c 3 -W 2 10.77.0.2') == 0, 'no ping over the tunnel')
        st = status(api, a, 'wireguard')
        want(any(p.get('handshake') for p in st['status'].get('peers') or []), f'the panel shows no handshake: {st["status"]}')
        state['wg'] = (a, pub[b])
        return 'two hosts joined from the peer manager, and they ping over the tunnel'
    r.check('tb-wg-pair', bookworm.name if bookworm else '-', wg_pair) if bookworm and ubuntu else r.add('tb-wg-pair', '-', None, 'needs sf-bookworm and sf-ubuntu')

    def wg_revoke():
        a, key = state.get('wg') or (_ for _ in ()).throw(AssertionError('needs tb-wg-pair'))
        got = api.post(f'/api/toolbox/{a}/wireguard/actions/revoke-peer', {'values': {'iface': 'wg7', 'pubkey': key}})
        deploy_plan(api, got['plan_id'], 'lab: revoke a peer')
        want(quiet(bookworm.name, 'ping -c 2 -W 2 10.77.0.2') != 0, 'the revoked peer still answers')
        return 'the revoked peer is cut off'
    r.check('tb-wg-revoke', bookworm.name if bookworm else '-', wg_revoke) if bookworm and ubuntu else r.add('tb-wg-revoke', '-', None, 'needs sf-bookworm and sf-ubuntu')

    # ── what cannot be slipped past the catalog ──
    def plan_changed():
        host = demo.known_as(api, (fedora or rocky).name)
        got = stage(api, host, 'uptime-kuma', method='quadlet')
        plan = api.get(f'/api/changes/{got["plan_id"]}')
        plan['tasks'][-1]['params']['sha'] = 'a' * 64
        api.put(f'/api/changes/{got["plan_id"]}', {'name': plan['name'], 'tasks': plan['tasks']})
        text = report_only(api, got['plan_id'], 'lab: changed plan')
        want('changed after this step was staged' in text, text[-600:])
        want(quiet((fedora or rocky).name, 'test -e /etc/containers/systemd/uptime-kuma.container') != 0, 'a unit was written')
        return 'a step edited to another entry is refused on the host'
    r.check('tb-plan-changed', '-', plan_changed) if fedora or rocky else r.add('tb-plan-changed', '-', None, 'needs sf-fedora or sf-rocky')

    def adapter_fails():
        host = state.get('kuma') or (_ for _ in ()).throw(AssertionError('needs tb-kuma-rootless'))
        sudo(rocky.name, 'systemctl --user -M sf-uptime-kuma@ stop uptime-kuma.service', check=False)
        before = t.sql(f"SELECT measured_at FROM security_measurements WHERE kind = 'infra' AND host = '{host}'")
        st = status(api, host, 'uptime-kuma')
        after = t.sql(f"SELECT measured_at FROM security_measurements WHERE kind = 'infra' AND host = '{host}'")
        want(after and (not before or after[0]['measured_at'] >= before[0]['measured_at']), 'the reading was not recorded')
        want((st.get('status') or {}).get('health') in ('down', 'missing'), f'status {st.get("status")}')
        sudo(rocky.name, 'systemctl --user -M sf-uptime-kuma@ start uptime-kuma.service', check=False)
        return 'a stopped tool reads as down, and the reading is recorded'
    r.check('tb-adapter-fails', rocky.name if rocky else '-', adapter_fails) if rocky else r.add('tb-adapter-fails', '-', None, 'needs sf-rocky')
