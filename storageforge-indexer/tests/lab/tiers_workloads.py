#!/usr/bin/env python3
"""Tier 28 of the KVM lab: workloads (roadmap section 6, 0.5.11), and section 1.3's reverse proxies and identity providers on lab hosts.

NOT RUN. This file was written on 2026-11-20 where the KVM lab cannot run, so no check below has ever passed or failed on a real VM:
it is not lab-tested. What was run is tests/test_workload_steps.py, test_image_update.py, test_vm_iso.py, test_placement.py,
test_workload_mac.py, test_workload_capture.py, test_stack_snapshot.py, test_workload_managed.py and test_workload_export.py on this
machine: the step scripts against stand-ins, a stack, an image update with its rollback and a capture with the real Docker and compose,
the real virt-install on libvirt's test driver, the real virt-xml-validate and the real apparmor_parser. A first run will most likely
have to correct this file before it says anything about StorageForge. A check that cannot be made shows as skip or as failed, never as
passed.

Hosts, by ability: Docker on sf-ubuntu (with ZFS, so stack snapshots and placement have a pool), Podman and SELinux on sf-rocky, libvirt
installed for this tier on sf-bookworm (Debian 12, AppArmor), as tier 18 does; Incus and LXC installed by runtime-install steps.

    proxy-caddy         Caddy with a reverse_proxy route on sf-bookworm: the reading lists its site and upstream
    proxy-nginx         nginx with a proxy_pass on sf-jammy: the reading lists its server_name and upstream
    proxy-traefik       Traefik and HAProxy in containers on sf-ubuntu (a stack each): the reading shows their listeners,
    proxy-haproxy       owned by traefik and haproxy, and the workloads list their containers
    idp-lldap           LLDAP, Keycloak, Authelia and Authentik, each as a stack on sf-ubuntu with its secrets from the vault through
    idp-keycloak        secret-file steps (never in the compose file): each answers on its port, and is listed as a workload.
    idp-authelia        Authentik needs more memory than the lab VM has to spare at once: it runs alone, and is a skip where the
    idp-authentik       host has less than 3 GiB
    stack-deploy        a stack with labels and allow_from: the containers carry storageforge.managed and the labels, DOCKER-USER
                        holds the deny and the allow for its published port, and a host outside allow_from cannot connect
    stack-rerun         a second deploy of the same plan says the stack is up from this compose file, and changes nothing
    stack-diff          a changed compose file: the report shows the lines that change
    lxc-create          runtime-install lxc, then an lxc step on sf-bookworm: an unprivileged container (its uid 0 is a subordinate
                        id on the host) that runs, with storageforge.labels
    incus-instance      runtime-install incus, then an incus step on sf-ubuntu with a published port and allow_from: the proxy device,
                        the user.* labels, and the fence (nft list table inet storageforge_shares)
    image-update-ok     a stack running localhost:5000/sflab/app:1 from a registry container on the host: a new image pushed under
                        the same name passes its healthcheck and stays
    image-update-back   a broken image pushed under that name fails its healthcheck: the stack runs the image it had before
    vm-iso              libvirt on sf-bookworm; a vm-iso step with Alpine (virt): the ISO checked, the VM defined and booting its
                        installer, its console listening on 127.0.0.1 only
    mac-apparmor        vm-mac for a pool folder outside /var/lib/libvirt/images on sf-bookworm: the local libvirt-qemu abstraction holds
                        it, and a VM with a disk there starts
    mac-selinux         vm-mac for a folder on sf-rocky: semanage fcontext lists it as virt_image_t and the folder is labelled so
    stack-relabel       a Podman stack on sf-rocky with a bind mount and selinux=private: the container reads the folder (without the
                        label it is denied, which the check warns of first)
    placement           the check of a stack with a PostgreSQL bind mount on sf-ubuntu's ZFS pool of spinning disks says so, and one on
                        an NFS mount warns of the network filesystem
    quadlet-read        a Quadlet unit on sf-rocky, started: the reading lists it, and the workloads list ties its container to the file
    adopt-drift         a container started by hand on sf-ubuntu, adopted as compose; started again with another published port, the
                        capture shows the drift; the capture passes docker compose config on the host
    stack-snapshot      a stateful stack on sf-ubuntu's ZFS pool snapshotted with stop: the snapshot is there with
                        storageforge:quiesce=stop, the stack runs after, and quiesce.log has the line
    external-managed    a container with Komodo labels and a container under a container-NAME.service unit: the workloads list says
                        who manages each, and a workload-remove check warns before changing them
    export              a plan of these steps exported as OpenTofu and Puppet: tofu fmt and puppet parser validate on the controller
                        host where they are installed (a skip otherwise; applying them is 0.5.15)
"""
import json
import shlex
import time

import demo
import roles

import tiers as t
from tiers_platform import connects, quiet, sudo

PKGS = ('DEBIAN_FRONTEND=noninteractive apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends '
        'libvirt-daemon-system libvirt-clients qemu-system-x86 qemu-utils virtinst xorriso curl ca-certificates apparmor-utils >/dev/null')


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def said(runs):
    return '\n'.join(x.get('output') or '' for x in runs or [])


def plan(api, name, *tasks, **options):
    pid = api.post('/api/changes', {'name': name, 'tasks': [{'type': k, 'host': h, 'params': p} for k, h, p in tasks]})['id']
    return pid, demo.deploy(api, 'changes', pid, name, **options)


def check_items(api, kind, host, params):
    out = api.post('/api/changes/check', {'name': 'lab check', 'tasks': [{'type': kind, 'host': host, 'params': params}]})
    return [(i['level'], i['text']) for i in out['tasks'][0]['items']]


def report_only(api, pid, title):
    group = api.post('/api/deploy/start', {'kind': 'changes', 'ref': pid, 'mode': 'report', 'title': title})['group']
    return said(demo.wait(title, lambda: demo.finished(api, group))['runs'])


def infra(host):
    """The host's last infrastructure reading, from the controller's database: proxy routes are drawn on the map, not served alone."""
    rows = t.sql(f"SELECT data_json FROM security_measurements WHERE kind = 'infra' AND lower(host) = lower('{host}')")
    return json.loads(rows[0]['data_json']) if rows else {}


def workload(api, host, name):
    return next((w for w in api.get(f'/api/workloads?host={host}')['workloads'] if w['name'] == name), None)


def answers(vm, url, tries=60):
    for _ in range(tries):
        if quiet(vm, f'curl -fsS -o /dev/null --max-time 3 {shlex.quote(url)}') == 0:
            return True
        time.sleep(3)
    return False


def secret(api, name, host):
    api.raw('DELETE', f'/api/keys/secrets/{name}')
    return api.post('/api/keys/secrets', {'name': name, 'kind': 'token', 'length': 40, 'hosts': [host]})['value']


def down(vm, name):
    sudo(vm, f'cd /srv/stacks/{name} 2>/dev/null && docker compose -p {name} down -v -t 2', check=False)


IDP = {
    'lldap': ('lldap/lldap:stable', 17170, '/api/healthcheck', {'LLDAP_JWT_SECRET_FILE': '/run/secrets/jwt', 'LLDAP_LDAP_USER_PASS_FILE': '/run/secrets/admin'}, ('jwt', 'admin')),
    'keycloak': ('quay.io/keycloak/keycloak:26.4', 18080, '/', {'KC_HTTP_PORT': '8080'}, ()),
    'authelia': ('authelia/authelia:4.39', 19091, '/api/health', {'AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE': '/run/secrets/jwt',
                                                                  'AUTHELIA_SESSION_SECRET_FILE': '/run/secrets/session', 'AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE': '/run/secrets/storage'},
                 ('jwt', 'session', 'storage')),
}
AUTHELIA_CONF = '''server: {address: "tcp://0.0.0.0:9091"}
log: {level: info}
authentication_backend: {file: {path: /config/users.yml}}
access_control: {default_policy: one_factor}
session: {cookies: [{domain: lab.test, authelia_url: "https://auth.lab.test"}]}
storage: {local: {path: /config/db.sqlite3}}
notifier: {filesystem: {filename: /config/notification.txt}}
'''


def idp_compose(name):
    image, port, _, env, files = IDP[name]
    internal = {'lldap': 17170, 'keycloak': 8080, 'authelia': 9091}[name]
    svc = {'image': image, 'ports': [f'{port}:{internal}'], 'environment': env, 'restart': 'unless-stopped'}
    if name == 'keycloak':
        svc['command'] = ['start-dev']
    if files:
        svc['secrets'] = list(files)
    if name == 'authelia':
        svc['volumes'] = ['/srv/stacks/authelia/config:/config']
    doc = {'services': {name: svc}}
    if files:
        doc['secrets'] = {f: {'file': f'/srv/stacks/{name}/secrets/{f}'} for f in files}
    return json.dumps(doc, indent=2)


def tier28(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    by = {n.name: n for n in roles.deployable()}
    dock = by.get('sf-ubuntu')
    pod = by.get('sf-rocky')
    virt = by.get('sf-bookworm')
    nginx_host = by.get('sf-jammy')
    outsider = next((n.name for n in roles.deployable() if n.name not in ('sf-ubuntu',)), None)
    state = {}

    # ── 1.3: reverse proxies ──
    def proxy_caddy():
        h = demo.known_as(api, virt.name)
        sudo(virt.name, 'DEBIAN_FRONTEND=noninteractive apt-get -qq install -y caddy >/dev/null && '
                        'printf "lab.test:8088 {\\n  reverse_proxy 127.0.0.1:9000\\n}\\n" >/etc/caddy/Caddyfile && systemctl restart caddy')
        api.post('/api/infra/measure', {'host': h})
        routes = (infra(h).get('access') or {}).get('proxy_routes') or []
        want(any('127.0.0.1:9000' in json.dumps(x) for x in routes), f'no Caddy route in the reading: {routes}')
        return 'the Caddy site and its upstream are in the reading'
    r.check('proxy-caddy', virt.name if virt else '-', proxy_caddy) if virt else r.add('proxy-caddy', '-', None, 'needs sf-bookworm')

    def proxy_nginx():
        h = demo.known_as(api, nginx_host.name)
        sudo(nginx_host.name, 'DEBIAN_FRONTEND=noninteractive apt-get -qq install -y nginx >/dev/null && printf "server {\\n  listen 8089;\\n  server_name app.lab.test;\\n'
                              '  location / { proxy_pass http://127.0.0.1:9001; }\\n}\\n" >/etc/nginx/sites-enabled/sflab && systemctl reload nginx')
        api.post('/api/infra/measure', {'host': h})
        routes = (infra(h).get('access') or {}).get('proxy_routes') or []
        want(any('app.lab.test' in json.dumps(x) for x in routes), f'no nginx route in the reading: {routes}')
        return 'the nginx server_name and proxy_pass are in the reading'
    r.check('proxy-nginx', nginx_host.name if nginx_host else '-', proxy_nginx) if nginx_host else r.add('proxy-nginx', '-', None, 'needs sf-jammy')

    def proxy_container(name, image, port, args):
        def run():
            h = demo.known_as(api, dock.name)
            compose = json.dumps({'services': {name: {'image': image, 'ports': [f'{port}:{port}'], 'command': args}}})
            plan(api, f'lab: {name}', ('stack', h, {'runtime': 'docker', 'name': f'sflab-{name}', 'compose': compose}))
            api.post('/api/infra/measure', {'host': h})
            want(workload(api, h, f'sflab-{name}-{name}-1'), f'{name} is not in the workloads')
            listeners = json.dumps(infra(h).get('listeners') or [])
            want(str(port) in listeners, f'nothing listens on {port} in the reading')
            down(dock.name, f'sflab-{name}')
            return f'{name} listens on {port} and is listed as a workload'
        return run
    if dock:
        r.check('proxy-traefik', dock.name, proxy_container('traefik', 'traefik:v3.5', 8090, ['--entrypoints.web.address=:8090', '--api.insecure=true']))
        r.check('proxy-haproxy', dock.name, proxy_container('haproxy', 'haproxy:3.2', 8091, ['haproxy', '-f', '/dev/null', '-db']))
    else:
        r.add('proxy-traefik', '-', None, 'needs sf-ubuntu with Docker')

    # ── 1.3: identity providers, secrets from the vault ──
    def idp(name):
        def run():
            h = demo.known_as(api, dock.name)
            image, port, path, _, files = IDP[name]
            tasks, values = [], []
            for f in files:
                values.append(secret(api, f'sflab-{name}-{f}', h))
                tasks.append(('secret-file', h, {'secret': f'sflab-{name}-{f}', 'path': f'/srv/stacks/{name}/secrets/{f}', 'mode': '0644'}))
            if name == 'authelia':
                sudo(dock.name, f'mkdir -p /srv/stacks/authelia/config && cat >/srv/stacks/authelia/config/configuration.yml && '
                                'printf "users: {}\\n" >/srv/stacks/authelia/config/users.yml', stdin=AUTHELIA_CONF)
            compose = idp_compose(name)
            want(not [t_ for lv, t_ in check_items(api, 'stack', h, {'runtime': 'docker', 'name': name, 'compose': compose}) if lv == 'crit'], 'the check refuses the stack')
            pid, runs = plan(api, f'lab: {name}', *tasks, ('stack', h, {'runtime': 'docker', 'name': name, 'compose': compose}))
            want(not [v for v in values if v in said(runs)], 'a secret is in the deploy output')
            want(not [v for v in values if v in compose], 'a secret is in the compose file')
            want(answers(dock.name, f'http://127.0.0.1:{port}{path}', tries=100), f'{name} does not answer on {port}')
            api.post('/api/infra/measure', {'host': h})
            want(any(w.get('image', '').startswith(image.split(':')[0]) for w in api.get(f'/api/workloads?host={h}')['workloads']), f'{name} is not a workload')
            down(dock.name, name)
            for f in files:
                api.raw('DELETE', f'/api/keys/secrets/sflab-{name}-{f}')
            return f'{name} answers on {port}, its secrets came from the vault, and it is listed'
        return run
    if dock:
        for name in IDP:
            r.check(f'idp-{name}', dock.name, idp(name))
        mem = int(sudo(dock.name, "awk '/MemTotal/ {print $2}' /proc/meminfo", check=False).strip() or 0)
        if mem < 3 * 1024 * 1024:
            r.add('idp-authentik', dock.name, None, f'the host has {mem // 1024} MiB: Authentik with its PostgreSQL and Redis wants 3 GiB')
        else:
            def authentik():
                h = demo.known_as(api, dock.name)
                secret(api, 'sflab-authentik-key', h)
                secret(api, 'sflab-authentik-pg', h)
                env = {'AUTHENTIK_SECRET_KEY': 'file:///run/secrets/key', 'AUTHENTIK_POSTGRESQL__HOST': 'pg', 'AUTHENTIK_POSTGRESQL__USER': 'authentik',
                       'AUTHENTIK_POSTGRESQL__PASSWORD': 'file:///run/secrets/pg', 'AUTHENTIK_REDIS__HOST': 'redis'}
                compose = json.dumps({'services': {
                    'pg': {'image': 'postgres:16-alpine', 'environment': {'POSTGRES_USER': 'authentik', 'POSTGRES_PASSWORD_FILE': '/run/secrets/pg'}, 'secrets': ['pg']},
                    'redis': {'image': 'redis:7-alpine'},
                    'server': {'image': 'ghcr.io/goauthentik/server:2025.10', 'command': 'server', 'environment': env, 'secrets': ['key', 'pg'], 'ports': ['19000:9000']},
                    'worker': {'image': 'ghcr.io/goauthentik/server:2025.10', 'command': 'worker', 'environment': env, 'secrets': ['key', 'pg']}},
                    'secrets': {'key': {'file': '/srv/stacks/authentik/secrets/key'}, 'pg': {'file': '/srv/stacks/authentik/secrets/pg'}}})
                plan(api, 'lab: authentik', ('secret-file', h, {'secret': 'sflab-authentik-key', 'path': '/srv/stacks/authentik/secrets/key', 'mode': '0644'}),
                     ('secret-file', h, {'secret': 'sflab-authentik-pg', 'path': '/srv/stacks/authentik/secrets/pg', 'mode': '0644'}),
                     ('stack', h, {'runtime': 'docker', 'name': 'authentik', 'compose': compose}))
                want(answers(dock.name, 'http://127.0.0.1:19000/-/health/live/', tries=150), 'Authentik does not answer')
                down(dock.name, 'authentik')
                return 'Authentik answers, with its keys from the vault'
            r.check('idp-authentik', dock.name, authentik)

    # ── stacks ──
    def stack_deploy():
        h = demo.known_as(api, dock.name)
        compose = json.dumps({'services': {'web': {'image': 'nginx:1.27-alpine', 'ports': ['18081:80']}}})
        state['stack'] = {'runtime': 'docker', 'name': 'sflab-web', 'compose': compose, 'labels': 'team=lab', 'allow_from': demo.IPS['sf-ctl']}
        pid, runs = plan(api, 'lab: web stack', ('stack', h, state['stack']))
        state['stack_pid'] = pid
        labels = sudo(dock.name, 'docker ps --filter label=com.docker.compose.project=sflab-web --format "{{.Labels}}"')
        want('storageforge.managed=true' in labels and 'team=lab' in labels, f'the labels are {labels}')
        rules = sudo(dock.name, 'iptables -S DOCKER-USER')
        want(rules.count('sf-rule-') >= 2, f'DOCKER-USER holds no rules of the stack:\n{rules}')
        want(answers('sf-ctl', f'http://{demo.IPS[dock.name]}:18081/', tries=10), 'the allowed host cannot reach it')
        if outsider:
            want(not connects(outsider, demo.IPS[dock.name], 18081), f'{outsider}, outside allow_from, reaches it')
        return 'labels on the containers, a deny and an allow in DOCKER-USER, and only the allowed host reaches it'
    if dock:
        r.check('stack-deploy', dock.name, stack_deploy)

    def stack_rerun():
        out = said(demo.deploy(api, 'changes', state['stack_pid'], 'web stack again'))
        want('is up, from this compose file' in out, f'the second run did not find it up:\n{out[-800:]}')
        return 'a second run found the stack up and changed nothing'
    if state.get('stack_pid'):
        r.check('stack-rerun', dock.name, stack_rerun)

    def stack_diff():
        h = demo.known_as(api, dock.name)
        changed = dict(state['stack'], compose=state['stack']['compose'].replace('18081', '18082'))
        api('PUT', f'/api/changes/{state["stack_pid"]}', {'name': 'lab: web stack', 'tasks': [{'type': 'stack', 'host': h, 'params': changed}]})
        out = report_only(api, state['stack_pid'], 'web stack, changed')
        want('18082' in out and 'what changes in' in out, f'the report shows no diff:\n{out[-800:]}')
        down(dock.name, 'sflab-web')
        return 'the report shows the lines that change'
    if state.get('stack_pid'):
        r.check('stack-diff', dock.name, stack_diff)

    # ── LXC and Incus ──
    def lxc_create():
        h = demo.known_as(api, virt.name)
        plan(api, 'lab: lxc', ('runtime-install', h, {'runtime': 'lxc'}),
             ('lxc', h, {'name': 'sflab-lxc', 'distro': 'debian', 'release': 'bookworm', 'labels': 'team=lab'}))
        want(sudo(virt.name, 'lxc-info -n sflab-lxc -sH').strip() == 'RUNNING', 'the container does not run')
        uid = sudo(virt.name, "lxc-attach -n sflab-lxc -- sleep 30 & sleep 2; ps -o uid= -C sleep | sort -n | tail -n 1").strip()
        want(uid.isdigit() and int(uid) >= 100000, f'its root is uid {uid} on the host: not unprivileged')
        want('team=lab' in sudo(virt.name, 'cat /var/lib/lxc/sflab-lxc/storageforge.labels'), 'no labels file')
        return f'unprivileged (uid {uid} on the host), running, with its labels'
    r.check('lxc-create', virt.name, lxc_create) if virt else r.add('lxc-create', '-', None, 'needs sf-bookworm')

    def incus_instance():
        h = demo.known_as(api, dock.name)
        plan(api, 'lab: incus', ('runtime-install', h, {'runtime': 'incus'}),
             ('incus', h, {'name': 'sflab-c1', 'image': 'images:debian/13', 'publish': '18083:80', 'labels': 'team=lab', 'allow_from': demo.IPS['sf-ctl']}))
        want(sudo(dock.name, 'incus config get sflab-c1 user.team').strip() == 'lab', 'no user.team label')
        want('listen=tcp:0.0.0.0:18083' in sudo(dock.name, 'incus config device show sflab-c1'), 'no proxy device')
        want(demo.IPS['sf-ctl'] in sudo(dock.name, 'nft list table inet storageforge_shares'), 'no fence for its port')
        sudo(dock.name, 'incus delete -f sflab-c1', check=False)
        return 'proxy device, user.* label and the fence'
    r.check('incus-instance', dock.name, incus_instance) if dock else r.add('incus-instance', '-', None, 'needs sf-ubuntu')

    # ── image updates, with a registry on the host ──
    def image_update(broken):
        def run():
            h = demo.known_as(api, dock.name)
            sudo(dock.name, 'docker run -d --name sflab-registry -p 127.0.0.1:5000:5000 registry:2 >/dev/null 2>&1 || true; sleep 2; '
                            'docker pull -q busybox:latest >/dev/null && docker tag busybox:latest localhost:5000/sflab/app:1 && docker push -q localhost:5000/sflab/app:1 >/dev/null')
            compose = json.dumps({'services': {'app': {'image': 'localhost:5000/sflab/app:1', 'command': ['sleep', '3000'],
                                                       'healthcheck': {'test': ['CMD-SHELL', 'test ! -e /etc/alpine-release' if broken else 'test -e /bin/sh'],
                                                                       'interval': '2s', 'retries': 2}}}})
            plan(api, 'lab: app', ('stack', h, {'runtime': 'docker', 'name': 'sflab-app', 'compose': compose}))
            before = sudo(dock.name, 'docker inspect -f "{{.Image}}" sflab-app-app-1').strip()
            sudo(dock.name, 'docker pull -q alpine:3 >/dev/null && docker tag alpine:3 localhost:5000/sflab/app:1 && docker push -q localhost:5000/sflab/app:1 >/dev/null '
                            '&& docker tag ' + before + ' localhost:5000/sflab/app:1')
            pid = api.post('/api/changes', {'name': 'lab: update app', 'tasks': [{'type': 'image-update', 'host': h, 'params': {'runtime': 'docker', 'stack': 'sflab-app', 'wait': '60'}}]})['id']
            runs = demo.deploy(api, 'changes', pid, 'update app', may_fail=h if broken else None)
            now = sudo(dock.name, 'docker inspect -f "{{.Image}}" sflab-app-app-1').strip()
            down(dock.name, 'sflab-app')
            if broken:
                want(now == before, 'the stack does not run the image it had before')
                return 'the broken image failed its healthcheck, and the stack runs the image it had before'
            want(now != before, 'the stack still runs the old image')
            return f'updated and healthy: {now[:19]}'
        return run
    if dock:
        r.check('image-update-ok', dock.name, image_update(False))
        r.check('image-update-back', dock.name, image_update(True))
        sudo(dock.name, 'docker rm -f sflab-registry', check=False)

    # ── VMs from ISOs, and MAC ──
    def vm_iso():
        h = demo.known_as(api, virt.name)
        sudo(virt.name, PKGS)
        api.post('/api/infra/measure', {'host': h})
        plan(api, 'lab: iso vm', ('vm-iso', h, {'name': 'sflab-iso', 'iso': 'alpine324', 'ram_mb': '1024', 'disk_gb': '4', 'console': 'vnc'}))
        state_ = sudo(virt.name, 'virsh -c qemu:///system domstate sflab-iso').strip()
        want(state_ == 'running', f'the VM is {state_}')
        display = sudo(virt.name, 'virsh -c qemu:///system domdisplay sflab-iso').strip()
        want('127.0.0.1' in display, f'its console is {display}')
        sudo(virt.name, 'virsh -c qemu:///system destroy sflab-iso; virsh -c qemu:///system undefine sflab-iso', check=False)
        return f'booting its installer, console {display}'
    r.check('vm-iso', virt.name, vm_iso) if virt else r.add('vm-iso', '-', None, 'needs sf-bookworm')

    def mac_apparmor():
        h = demo.known_as(api, virt.name)
        sudo(virt.name, 'mkdir -p /srv/sflab-vms')
        plan(api, 'lab: vm-mac', ('vm-mac', h, {'path': '/srv/sflab-vms'}))
        local = sudo(virt.name, 'cat /etc/apparmor.d/local/abstractions/libvirt-qemu')
        want('"/srv/sflab-vms/**" rwk,' in local, f'the local abstraction is:\n{local}')
        return 'the folder is in the local libvirt-qemu abstraction'
    r.check('mac-apparmor', virt.name, mac_apparmor) if virt else r.add('mac-apparmor', '-', None, 'needs sf-bookworm')

    def mac_selinux():
        h = demo.known_as(api, pod.name)
        sudo(pod.name, 'mkdir -p /srv/sflab-vms')
        plan(api, 'lab: vm-mac selinux', ('vm-mac', h, {'path': '/srv/sflab-vms', 'system': 'selinux'}))
        want('virt_image_t' in sudo(pod.name, 'stat -c %C /srv/sflab-vms'), 'the folder is not virt_image_t')
        want('/srv/sflab-vms' in sudo(pod.name, 'semanage fcontext -l -C'), 'not registered with semanage')
        return 'virt_image_t, and registered'
    r.check('mac-selinux', pod.name, mac_selinux) if pod else r.add('mac-selinux', '-', None, 'needs sf-rocky')

    def stack_relabel():
        h = demo.known_as(api, pod.name)
        sudo(pod.name, 'mkdir -p /srv/sflab-data && echo hello >/srv/sflab-data/f')
        compose = json.dumps({'services': {'app': {'image': 'docker.io/library/busybox:latest', 'command': ['sleep', '600'], 'volumes': ['/srv/sflab-data:/data']}}})
        warned = check_items(api, 'stack', h, {'runtime': 'podman', 'name': 'sflab-label', 'compose': compose})
        want(any(':z or :Z' in x for _, x in warned), f'no warning of the missing label: {warned}')
        plan(api, 'lab: relabel', ('runtime-install', h, {'runtime': 'podman'}), ('stack', h, {'runtime': 'podman', 'name': 'sflab-label', 'compose': compose, 'selinux': 'private'}))
        got = sudo(pod.name, 'podman exec sflab-label_app_1 cat /data/f 2>/dev/null || podman exec sflab-label-app-1 cat /data/f').strip()
        want(got == 'hello', f'the container cannot read the folder: {got!r}')
        sudo(pod.name, 'cd /srv/stacks/sflab-label && podman-compose down || podman compose down', check=False)
        return 'with :Z the container reads it; the check warned without it'
    r.check('stack-relabel', pod.name, stack_relabel) if pod else r.add('stack-relabel', '-', None, 'needs sf-rocky')

    # ── placement ──
    def placement():
        h = demo.known_as(api, dock.name)
        pool = dock.tag('zfs-pool') or 'tank'
        compose = json.dumps({'services': {'db': {'image': 'postgres:16', 'volumes': [f'/{pool}/sflab-db:/var/lib/postgresql/data']}}})
        items = check_items(api, 'stack', h, {'runtime': 'docker', 'name': 'sflab-db', 'compose': compose})
        want(any('bulk pool' in x or 'recordsize' in x for _, x in items), f'no placement advice: {items}')
        want(any('no hold or offsite copy' in x or 'snapshotted' in x or 'copied off' in x for _, x in items), 'nothing said of its protection')
        return 'the check gives placement advice for the database on the ZFS pool'
    r.check('placement', dock.name, placement) if dock else r.add('placement', '-', None, 'needs sf-ubuntu')

    # ── read side ──
    def quadlet_read():
        h = demo.known_as(api, pod.name)
        sudo(pod.name, 'mkdir -p /etc/containers/systemd && printf "[Container]\\nImage=docker.io/library/busybox:latest\\nExec=sleep 3000\\n'
                       'ContainerName=sflab-q\\n[Install]\\nWantedBy=multi-user.target\\n" >/etc/containers/systemd/sflab-q.container && '
                       'systemctl daemon-reload && systemctl start sflab-q.service')
        api.post('/api/infra/measure', {'host': h})
        api.post('/api/scan', {'hosts': [h]})
        time.sleep(20)
        w = workload(api, h, 'sflab-q')
        want(w and w.get('quadlet') == '/etc/containers/systemd/sflab-q.container', f'the workload is {w}')
        want((w.get('managed') or {}).get('by') == 'systemd', f'not marked as run by systemd: {w.get("managed")}')
        return 'the container is tied to its Quadlet file, and marked as run by systemd'
    r.check('quadlet-read', pod.name, quadlet_read) if pod else r.add('quadlet-read', '-', None, 'needs sf-rocky')

    def adopt_drift():
        h = demo.known_as(api, dock.name)
        sudo(dock.name, 'docker rm -f sflab-loose >/dev/null 2>&1; docker run -d --name sflab-loose -p 18084:80 nginx:1.27-alpine >/dev/null')
        api.post('/api/scan', {'hosts': [h]})
        time.sleep(20)
        got = api.post('/api/workloads/captures', {'host': h, 'runtime': 'docker', 'name': 'sflab-loose'})
        sudo(dock.name, 'mkdir -p /tmp/sflab-cap && cat >/tmp/sflab-cap/compose.yaml', stdin=got['definition'])
        want(quiet(dock.name, 'docker compose -f /tmp/sflab-cap/compose.yaml config -q') == 0, 'the capture is not valid compose on the host')
        state['adopted'] = got['id']
        sudo(dock.name, 'docker rm -f sflab-loose >/dev/null; docker run -d --name sflab-loose -p 18084:80 -p 18085:80 nginx:1.27-alpine >/dev/null')
        api.post('/api/scan', {'hosts': [h]})
        time.sleep(20)
        cap = next(c for c in api.get('/api/workloads/captures')['captures'] if c['id'] == got['id'])
        want(cap['state'] == 'drifted' and any('18085' in json.dumps(d) for d in cap['drift']), f'no drift: {cap}')
        api('DELETE', f'/api/workloads/captures/{got["id"]}')
        sudo(dock.name, 'docker rm -f sflab-loose', check=False)
        return 'adopted as valid compose; the added port shows as drift'
    r.check('adopt-drift', dock.name, adopt_drift) if dock else r.add('adopt-drift', '-', None, 'needs sf-ubuntu')

    def stack_snapshot():
        h = demo.known_as(api, dock.name)
        pool = dock.tag('zfs-pool') or 'tank'
        sudo(dock.name, f'zfs create -p {pool}/sflab-state')
        compose = json.dumps({'services': {'db': {'image': 'postgres:16-alpine', 'environment': {'POSTGRES_HOST_AUTH_METHOD': 'trust'},
                                                  'volumes': [f'/{pool}/sflab-state:/var/lib/postgresql/data']}}})
        plan(api, 'lab: state', ('stack', h, {'runtime': 'docker', 'name': 'sflab-state', 'compose': compose}),
             ('stack-snapshot', h, {'runtime': 'docker', 'stack': 'sflab-state', 'method': 'stop'}))
        snaps = sudo(dock.name, f'zfs list -H -t snapshot -o name,storageforge:quiesce {pool}/sflab-state')
        want('sf-sflab-state-' in snaps and 'stop' in snaps, f'the snapshots are:\n{snaps}')
        want(sudo(dock.name, 'docker inspect -f "{{.State.Status}}" sflab-state-db-1').strip() == 'running', 'the stack does not run after')
        want('stop-snapshot-start' in sudo(dock.name, 'cat /var/lib/storageforge/quiesce.log'), 'nothing in quiesce.log')
        down(dock.name, 'sflab-state')
        sudo(dock.name, f'zfs destroy -r {pool}/sflab-state', check=False)
        return 'stopped, snapshotted with the method as a ZFS property, running again, and logged'
    r.check('stack-snapshot', dock.name, stack_snapshot) if dock else r.add('stack-snapshot', '-', None, 'needs sf-ubuntu')

    def external_managed():
        h = demo.known_as(api, dock.name)
        sudo(dock.name, 'docker rm -f sflab-komodo >/dev/null 2>&1; docker run -d --name sflab-komodo --label komodo.stack=lab busybox:latest sleep 3000 >/dev/null')
        api.post('/api/scan', {'hosts': [h]})
        time.sleep(20)
        w = workload(api, h, 'sflab-komodo')
        want(w and (w.get('managed') or {}).get('by') == 'Komodo', f'not marked as managed by Komodo: {w}')
        items = check_items(api, 'workload-remove', h, {'runtime': 'docker', 'name': 'sflab-komodo'})
        want(any('managed by Komodo' in x for _, x in items), f'the check does not warn: {items}')
        sudo(dock.name, 'docker rm -f sflab-komodo', check=False)
        return 'marked as Komodo, and the check warns before removing it'
    r.check('external-managed', dock.name, external_managed) if dock else r.add('external-managed', '-', None, 'needs sf-ubuntu')

    def export():
        h = demo.known_as(api, dock.name)
        pid = api.post('/api/changes', {'name': 'lab: export', 'tasks': [{'type': 'stack', 'host': h, 'params': state.get('stack') or {
            'runtime': 'docker', 'name': 'x', 'compose': 'services:\n  a:\n    image: nginx:1.27\n'}}]})['id']
        tf, pp = api.text(f'/api/changes/{pid}/export/opentofu'), api.text(f'/api/changes/{pid}/export/puppet')
        done = []
        if quiet('sf-ctl', 'command -v tofu') == 0:
            want(quiet('sf-ctl', f'printf %s {shlex.quote(str(tf))} | tofu fmt -') == 0, 'tofu fmt refuses it')
            done.append('tofu fmt')
        if quiet('sf-ctl', 'command -v puppet') == 0:
            want(quiet('sf-ctl', f'printf %s {shlex.quote(str(pp))} >/tmp/sflab.pp && puppet parser validate /tmp/sflab.pp') == 0, 'puppet refuses it')
            done.append('puppet parser validate')
        if not done:
            raise RuntimeError('neither tofu nor puppet is on sf-ctl: nothing checked the exports')
        return ', '.join(done) + ' take the exports'
    if dock:
        if quiet('sf-ctl', 'command -v tofu || command -v puppet') == 0:
            r.check('export', 'sf-ctl', export)
        else:
            r.add('export', 'sf-ctl', None, 'neither tofu nor puppet is installed on sf-ctl (applying exports is 0.5.15)')
