#!/usr/bin/env python3
"""The tunnel checks of lab tier 21: exposure through a tunnel, and the two steps that start one from a secret in the vault.

NOT RUN. This file was written where the KVM lab cannot run, so no check below has ever passed or failed on a real VM: it is not lab-tested.

And not against the real services either way: Cloudflare Tunnel and ngrok need an account, and the lab has no Pangolin server. So
`cloudflared` and `newt` on the lab host are STAND-INS, small scripts under their names that take the same arguments and stay
running. What these checks can show with them is everything on StorageForge's side of the program:

    tunnel-exposure     a service bound to loopback, a cloudflared configuration that publishes it and a process of that name: the
                        scan and the infrastructure reading then say the service is reachable from any address, in /api/exposure and
                        in the security posture, and say it no longer is once the tunnel is gone
    tunnel-token-file   the cloudflare-tunnel step through the whole deploy path, on real systemd: the token is in a file of mode 600
                        owned by root, in no process's arguments, in no plan, script or run output, and gone again with state absent
    newt-secret-file    the same for pangolin-site and Newt's configuration file

The token gets to the host as `vault send-secret` sends it, on ssh's stdin into /run/storageforge/secrets, but by the lab's own ssh:
send-secret logs in with a key file of the operator's, and the lab's controller container has none.

What stays untested until someone runs them against the real thing: that today's cloudflared accepts --token-file as written here,
that Newt reads CONFIG_FILE as its documentation says, and what Cloudflare and Pangolin then publish.
"""
import json
import shlex

import demo

import tiers as t  # noqa: F401  (for the path set-up, as the other tier files do)
from tiers_platform import sudo

PORT = 18321
TOKEN = 'eyJhIjoiTEFCTEFCTEFCbm90QVJlYWxUdW5uZWxUb2tlbjAwMDAwMDAwMDAwMDAwMDAwMDAwIn0='
SITE_SECRET = 'labsecretnotarealone000000000000000000000000000000000000'
CONFIG = f'tunnel: 6ff42ae2-0000-4000-8000-labstandin00\ningress:\n  - hostname: lab.example.invalid\n    service: http://localhost:{PORT}\n  - service: http_status:404\n'
# cloudflared as far as the step and the scan can tell: it has --token-file, and it runs for as long as it can read the file it names
CLOUDFLARED = r'''#!/bin/bash
case "$*" in
  "tunnel run --help") echo "   --token value"; echo "   --token-file value   Filepath at which to read the tunnel token" ;;
  "--version") echo "cloudflared version 0.0.0 (a stand-in of the StorageForge lab)" ;;
  *) while [ $# -gt 0 ]; do [ "$1" = --token-file ] && f=$2; shift; done; [ -z "${f:-}" ] || [ -r "$f" ] || exit 1; trap "kill \$!" TERM; sleep 86400 & wait ;;   # no exec: it keeps this name, which pgrep -x goes by
esac
'''
NEWT = r'''#!/bin/bash
[ -r "${CONFIG_FILE:-/nonexistent}" ] && grep -q secret "$CONFIG_FILE" || exit 1
trap "kill \$!" TERM; sleep 86400 & wait
'''


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def stand_in(node, name, text):
    sudo(node.name, f'command -v {name} >/dev/null && ! grep -q "stand-in\\|CONFIG_FILE" "$(command -v {name})" && exit 3; cat >/usr/local/bin/{name} && chmod 755 /usr/local/bin/{name}', stdin=text)


def secret_to(node, name, value):
    """As vault send-secret writes it: on stdin, into memory, mode 600."""
    demo.ssh('sf-ctl', f'{demo.COMPOSE} exec -T storageforge storageforge-index vault secret-add {name}', stdin=value + '\n', check=False)
    sudo(node.name, f'umask 077; mkdir -p /run/storageforge/secrets && chmod 700 /run/storageforge/secrets && cat >/run/storageforge/secrets/{name}', stdin=value + '\n')


def nowhere(node, secret, *texts):
    args = sudo(node.name, 'ps -eo args')
    want(secret not in args, 'the secret is in the arguments of a process on the host')
    for text in texts:
        want(secret not in (text if isinstance(text, str) else json.dumps(text)), 'the secret is in a plan, a script or the output of a run')


def checks(r, api, node):
    name = demo.known_as(api, node.name)

    def exposure():
        stand_in(node, 'cloudflared', CLOUDFLARED)
        sudo(node.name, f"nohup python3 -m http.server {PORT} --bind 127.0.0.1 >/dev/null 2>&1 & mkdir -p /etc/cloudflared && cat >/etc/cloudflared/config.yml; nohup cloudflared tunnel run >/dev/null 2>&1 & sleep 2", stdin=CONFIG)
        try:
            demo.scan(api, [node.ip])
            api.post('/api/infra/measure', {'host': name})
            rep = api.get(f'/api/exposure?host={name}')['hosts'][0]
            item = next((i for i in rep['items'] if i['port'] == PORT), None)
            want(item and item['level'] == 'any' and item.get('tunnel') == 'https://lab.example.invalid', f'a loopback service a tunnel publishes is not shown as public: {item}')
            want([x for x in rep['tunnels'] if x['public'] == 'https://lab.example.invalid' and x['level'] == 'any'], f'the tunnel is not listed: {rep["tunnels"]}')
            said = api.get(f'/api/security/posture?host={name}')['hosts'][0]['public']
            want(any('Public through Cloudflare Tunnel: https://lab.example.invalid' in s for s in said), f'the security view does not say it: {said}')
        finally:
            sudo(node.name, f'pkill -x cloudflared; pkill -f "http.server {PORT}"; rm -rf /etc/cloudflared/config.yml; true', check=False)
        api.post('/api/infra/measure', {'host': name})
        rep = api.get(f'/api/exposure?host={name}')['hosts'][0]
        want(not rep['tunnels'] and not [i for i in rep['items'] if i['port'] == PORT and i['level'] == 'any'], 'the tunnel is gone and the view still says public')
        return 'a service on loopback was shown as reachable from any address while a tunnel published it, and not after (cloudflared was a stand-in)'
    r.check('tunnel-exposure', node.name, exposure)

    def token_file():
        stand_in(node, 'cloudflared', CLOUDFLARED)
        secret_to(node, 'lab-cf-token', TOKEN)
        tasks = [{'type': 'cloudflare-tunnel', 'host': name, 'params': {'secret': 'lab-cf-token'}}]
        pid = api.post('/api/changes', {'name': f'lab cloudflare tunnel on {node.name}', 'tasks': tasks})['id']
        try:
            runs = demo.deploy(api, 'changes', pid, f'cloudflare tunnel on {node.name}')
            want(sudo(node.name, 'systemctl is-active storageforge-cloudflared').strip() == 'active', 'the unit is not running')
            want(sudo(node.name, 'stat -c "%a %U" /etc/cloudflared/storageforge-token').strip() == '600 root', 'the token file is not root-only')
            want(sudo(node.name, 'cat /etc/cloudflared/storageforge-token').strip() == TOKEN, 'the token file does not hold the token')
            want(sudo(node.name, 'ls /run/storageforge/secrets/lab-cf-token 2>/dev/null; true', check=False).strip() == '', 'the copy in /run was not removed')
            nowhere(node, TOKEN, api.text(f'/api/changes/{pid}/script'), api.get(f'/api/changes/{pid}'), runs)
        finally:
            off = api.post('/api/changes', {'name': f'lab cloudflare tunnel off {node.name}', 'tasks': [{'type': 'cloudflare-tunnel', 'host': name, 'params': {'secret': 'lab-cf-token', 'state': 'absent'}}]})['id']
            demo.deploy(api, 'changes', off, f'cloudflare tunnel off {node.name}')
            sudo(node.name, 'rm -f /usr/local/bin/cloudflared /run/storageforge/secrets/lab-cf-token', check=False)
        want(sudo(node.name, 'ls /etc/cloudflared/storageforge-token /etc/systemd/system/storageforge-cloudflared.service 2>/dev/null; true', check=False).strip() == '', 'absent left the token or the unit')
        return 'systemd ran the stand-in from a token file of mode 600; the token was in no arguments, plan, script or output; absent removed it'
    r.check('tunnel-token-file', node.name, token_file)

    def newt_file():
        stand_in(node, 'newt', NEWT)
        secret_to(node, 'lab-pg-site', SITE_SECRET)
        params = {'secret': 'lab-pg-site', 'site_id': 'labsite0000000', 'endpoint': 'https://pangolin.lab.invalid'}
        pid = api.post('/api/changes', {'name': f'lab pangolin site on {node.name}', 'tasks': [{'type': 'pangolin-site', 'host': name, 'params': params}]})['id']
        try:
            runs = demo.deploy(api, 'changes', pid, f'pangolin site on {node.name}')
            want(sudo(node.name, 'systemctl is-active storageforge-newt').strip() == 'active', 'the unit is not running')
            want(sudo(node.name, 'stat -c "%a %U" /etc/newt/storageforge.json').strip() == '600 root', 'the configuration is not root-only')
            conf = json.loads(sudo(node.name, 'cat /etc/newt/storageforge.json'))
            want(conf == {'id': params['site_id'], 'secret': SITE_SECRET, 'endpoint': params['endpoint']}, 'the configuration is not what Newt is documented to read')
            want(SITE_SECRET not in sudo(node.name, f'tr "\\0" "\\n" </proc/$(systemctl show -p MainPID --value storageforge-newt)/environ'), 'the secret is in the environment of Newt')
            nowhere(node, SITE_SECRET, api.text(f'/api/changes/{pid}/script'), api.get(f'/api/changes/{pid}'), runs)
        finally:
            off = api.post('/api/changes', {'name': f'lab pangolin site off {node.name}', 'tasks': [{'type': 'pangolin-site', 'host': name, 'params': {'secret': 'lab-pg-site', 'state': 'absent'}}]})['id']
            demo.deploy(api, 'changes', off, f'pangolin site off {node.name}')
            sudo(node.name, f'rm -f /usr/local/bin/newt /run/storageforge/secrets/{shlex.quote("lab-pg-site")}', check=False)
        want(sudo(node.name, 'ls /etc/newt/storageforge.json /etc/systemd/system/storageforge-newt.service 2>/dev/null; true', check=False).strip() == '', 'absent left the configuration or the unit')
        return 'systemd ran the stand-in from a configuration file of mode 600; the secret was in no arguments, environment, plan, script or output'
    r.check('newt-secret-file', node.name, newt_file)
