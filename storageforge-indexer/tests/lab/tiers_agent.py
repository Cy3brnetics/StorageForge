#!/usr/bin/env python3
"""Tier 24 of the KVM lab: the optional agent's base (roadmap section 11.1, and the rows of 11.6 that are about it) on real hosts.

NOT RUN. This file was written where the KVM lab cannot run, so no check below has ever passed or failed on a real VM: it is not
lab-tested. What was run is tests/test_agent.py on one machine: the setup script in bash, the real storageforge-agentctl and agent
against a folder standing for a host, and the real image under the real Docker.

What a real host adds to that, and this tier is for: real accounts and a real sudoers file read by sudo, sshd's forced command, Podman
without root with a session that lingers, the distributions' own package managers, SELinux on the dnf hosts, and LXC on Proxmox VE.

**What the lab's build has to provide first, and does not yet** (lab.sh is not changed by this file):

    1. the agent's programs and image built with a release key made for the lab (agent/build.sh and the Dockerfile's `agent` stage
       with STORAGEFORGE_RELEASE_SIGNERS / AGENT_RELEASE_SIGNERS naming the lab key's signers file)
    2. that image in a registry every lab VM can pull from by digest (a registry on sf-ctl, and the VMs told it is plain HTTP)
    3. the lab's server given STORAGEFORGE_AGENT_IMAGE (the digest), STORAGEFORGE_AGENT_IMAGE_SIG (the lab key's signature of it) and
       STORAGEFORGE_AGENT_DIR (the programs)

Until then /api/agents names no image and every check here shows as skip with that reason, not as a pass.

    off             the agent is off for every host until it is switched on for one
    docker group    with the managing user in the docker group the setup is refused, with the reason, and nothing is installed
    install         switched on and installed: on a host with Docker, a host with Podman (it runs without root there), and a host with
                    no runtime, where the install stops, says Podman will be installed, and installs it only when told
    as sfagent      the agent's process is sfagent, with no capability, cannot gain any, and sfagent is in no group that gives root and
                    has no sudo
    one line        the managing user can run storageforge-agentctl through sudo with no arguments and nothing else: not docker, not
                    podman, not a shell, not storageforge-agentctl with an argument; and what it sends unsigned is refused
    no socket       no runtime's socket is in the container, its root is read-only, and it has no network
    pve             on Proxmox VE the agent runs in an unprivileged LXC container made by pct, and Podman was never installed
    stop, remove    stopped it stays stopped; removed, the accounts, the sudoers line and the program are gone, and scans still work

The checks of the tunnel, the receiver, the plugins and wipe-and-stop are sections 11.2 to 11.4, and belong to this tier when built.
"""
import shlex

import demo
import roles

import tiers as t  # noqa: F401  (for the path set-up, as the other tier files do)
from tiers_platform import sudo

MANAGER, AGENT = 'storageforge-agentctl', 'sfagent'
CTL = '/usr/local/sbin/storageforge-agentctl'
ENDED = ('running', 'needs-podman', 'failed')


def want(ok, text):
    if not ok:
        raise AssertionError(text)


def row(api, name):
    return next(a for a in api.get('/api/agents')['agents'] if a['host'] == name)


def install(api, name, **body):
    """Start an install and wait for it to end one way or another. Returns the agent's row."""
    api.post(f'/api/agents/{name}/install', body)
    return demo.wait(f'the agent on {name}', lambda: (lambda a: a if a['state'] in ENDED and a['state'] != 'on' else None)(row(api, name)), timeout=1200)


def has(node, program):
    return sudo(node.name, f'command -v {shlex.quote(program)} >/dev/null 2>&1 && echo yes; true', check=False).strip() == 'yes'


def agent_pid(node):
    out = sudo(node.name, 'pgrep -f "^/usr/bin/storageforge-agent run" | head -n 1; true', check=False).strip()
    want(out.isdigit(), 'no storageforge-agent process on the host')
    return out


def status_of(node, pid):
    text = sudo(node.name, f'cat /proc/{pid}/status')
    return dict(line.split(':\t', 1) for line in text.splitlines() if ':\t' in line)


def tier24(r):
    api = demo.sign_in()
    demo.scan_everything(api)
    demo.set_up_deploy_access(api)
    listed = api.get('/api/agents')
    if not listed.get('image'):
        r.add('agent', '-', None, 'the lab server is given no agent image: the lab build does not publish one yet (see the top of tiers_agent.py)')
        return
    vms = [n for n in roles.deployable() if not n.can('appliance')]
    with_docker = next((n for n in vms if has(n, 'docker')), None)
    with_podman = next((n for n in vms if has(n, 'podman') and not has(n, 'docker')), None)
    bare = next((n for n in vms if not any(has(n, p) for p in ('docker', 'podman', 'lxc-create', 'incus', 'pct'))), None)
    pve = next((n for n in roles.having('proxmox') if n.can('deploy')), None)

    def off():
        on = [a['host'] for a in listed['agents'] if a['enabled']]
        want(not on, f'the agent is on for {on} before anyone switched it on')
        status, out = api.raw('POST', f'/api/agents/{demo.known_as(api, vms[0].name)}/install', {})
        if status == 403 and out.get('reauth'):
            api.raw('POST', '/api/reauth', {'password': api.password})
            status, out = api.raw('POST', f'/api/agents/{demo.known_as(api, vms[0].name)}/install', {})
        want(status == 409 and 'switched off' in out.get('error', ''), f'an install on a host with the agent off was not refused: {status} {out}')
        return 'off for every host, and an install is refused while it is'
    r.check('agent-off-by-default', '-', off)

    if with_docker:
        node, name = with_docker, demo.known_as(api, with_docker.name)

        def docker_group():
            api('PUT', f'/api/agents/{name}', {'enabled': True})
            sudo(node.name, f'id {MANAGER} >/dev/null 2>&1 || useradd --system --user-group --shell /bin/sh {MANAGER}; gpasswd -a {MANAGER} docker >/dev/null')
            try:
                got = install(api, name)
                want(got['state'] == 'failed', f'the setup went on with {MANAGER} in the docker group: {got["state"]}')
                want('is in the docker group, which is root on this host' in (got.get('detail') or ''), f'the reason was not given: {got.get("detail")}')
                want(not has(node, CTL), 'storageforge-agentctl was installed although the setup refused')
                want(sudo(node.name, 'ls /etc/sudoers.d/storageforge-agentctl 2>/dev/null; true', check=False).strip() == '', 'a sudoers line was written although the setup refused')
            finally:
                sudo(node.name, f'gpasswd -d {MANAGER} docker >/dev/null; userdel {MANAGER} 2>/dev/null; true', check=False)
            return 'refused before anything was installed, naming the group and how to leave it'
        r.check('agent-refused-in-docker-group', node.name, docker_group)

    def checks_on(node, expect):
        name = demo.known_as(api, node.name)

        def installed():
            api('PUT', f'/api/agents/{name}', {'enabled': True})
            got = install(api, name)
            if expect == 'podman-rootless' and node is bare:
                want(got['state'] == 'needs-podman', f'a host with no runtime was not stopped at the notice: {got["state"]}')
                want('Podman will be installed' in (got.get('detail') or ''), 'the user was not told Podman will be installed')
                want(not has(node, 'podman'), 'Podman was installed before anyone said so')
                got = install(api, name, install_podman=True)
            want(got['state'] == 'running', f'the agent is {got["state"]}: {got.get("detail")}')
            want(got['runtime'] == expect, f'the agent runs under {got["runtime"]}, expected {expect}')
            said = api.post(f'/api/agents/{name}/status')
            want(said['running'] and said['key_matches'], f'the host does not say it runs with the pinned key: {said}')
            return f'running under {got["runtime"]}, with the key {got["fingerprint"]} pinned'
        r.check('agent-install', node.name, installed)

        def as_sfagent():
            pid = agent_pid(node)
            s = status_of(node, pid)
            uid = sudo(node.name, f'id -u {AGENT}').strip()
            # under LXC and Podman the process is in a user namespace: its uid as the host sees it is what /proc shows here
            want(s['Uid'].split()[0] == uid, f'the agent runs as uid {s["Uid"].split()[0]}, and {AGENT} is {uid}')
            want(uid != '0', f'{AGENT} is root')
            want(int(s['CapEff'], 16) == 0 and int(s['CapPrm'], 16) == 0, f'the agent holds capabilities: {s["CapEff"]} {s["CapPrm"]}')
            want(s['NoNewPrivs'].strip() == '1', 'the agent can gain privileges')
            groups = sudo(node.name, f'id -nG {AGENT}').split()
            want(not set(groups) & {'docker', 'lxd', 'incus-admin', 'sudo', 'wheel', 'admin', 'root'}, f'{AGENT} is in {groups}')
            may = sudo(node.name, f'sudo -l -U {AGENT} 2>&1; true', check=False)
            want('not allowed to run sudo' in may, f'{AGENT} has sudo: {may[-200:]}')
            if expect == 'podman-rootless':
                owner = sudo(node.name, f'ps -o user= -p "$(pgrep -u {AGENT} -x conmon | head -n 1)"; true', check=False).strip()
                want(owner == AGENT, f'the container is not run by {AGENT} itself: conmon belongs to {owner or "nobody found"}')
            return f'uid {uid}, no capability, no new privileges, in {groups}, no sudo'
        r.check('agent-runs-as-sfagent', node.name, as_sfagent)

        def one_line():
            want(sudo(node.name, 'cat /etc/sudoers.d/storageforge-agentctl').strip() == f'{MANAGER} ALL=(root) NOPASSWD: {CTL} ""', 'the sudoers file is not the one line')
            as_manager = f'runuser -u {MANAGER} --'
            for attempt in ('sudo -n docker ps', 'sudo -n podman ps', 'sudo -n sh -c id', 'sudo -n id', f'sudo -n {CTL} status', f'sudo -n {CTL} --version', 'docker ps', 'cat /etc/shadow'):
                out = sudo(node.name, f'{as_manager} {attempt} >/dev/null 2>&1; echo $?', check=False).strip()
                want(out not in ('', '0'), f'{MANAGER} could run: {attempt}')
            # the one thing it may run, given something that is no signed request
            out = sudo(node.name, f'printf "STORAGEFORGE-AGENTCTL 1\\n2\\n2\\n{{}}{{}}" | {as_manager} sudo -n {CTL} >/dev/null 2>&1; echo $?', check=False).strip()
            want(out == '97', f'an unsigned request was not refused with 97: {out}')
            keys = sudo(node.name, f'cat "$(getent passwd {MANAGER} | cut -d: -f6)/.ssh/authorized_keys"')
            want(keys.startswith(f'restrict,command="sudo -n {CTL}" '), 'the login key is not held to the one command')
            return 'sudo runs storageforge-agentctl with no arguments and nothing else, and it refuses what is not signed'
        r.check('agent-one-sudoers-line', node.name, one_line)

        def no_socket():
            pid = agent_pid(node)
            mounts = sudo(node.name, f'cat /proc/{pid}/mountinfo')
            want(not any(word in mounts for word in ('docker.sock', 'podman.sock', 'containerd', 'unix.socket', '/run/pve', 'lxd')), 'a runtime socket is mounted in the container')
            for path in ('run/docker.sock', 'var/run/docker.sock', 'run/podman/podman.sock', 'var/lib/incus/unix.socket', 'bin/sh', 'usr/bin/ssh'):
                want(sudo(node.name, f'test -e /proc/{pid}/root/{path} && echo there; true', check=False).strip() == '', f'/{path} is in the container')
            if expect in ('docker', 'podman-rootless', 'podman'):
                root = [line for line in mounts.splitlines() if line.split()[4] == '/']
                want(root and 'ro' in root[0].split()[5].split(','), 'the root filesystem is not read-only')
            links = sudo(node.name, f'nsenter -t {pid} -n ip -o link | wc -l').strip()
            want(links == '1', f'the container has {links} network interfaces, expected only lo')
            return 'no socket, no shell, no ssh, read-only root, no network but lo'
        r.check('agent-no-socket-inside', node.name, no_socket)

        def stop_remove():
            api.post(f'/api/agents/{name}/stop')
            want(sudo(node.name, 'pgrep -f "^/usr/bin/storageforge-agent run"; true', check=False).strip() == '', 'the agent still runs after stop')
            want(not api.post(f'/api/agents/{name}/status')['running'], 'the host says it runs after stop')
            api.post(f'/api/agents/{name}/start')
            agent_pid(node)
            got = api('DELETE', f'/api/agents/{name}')
            want(not got['problems'], f'removing left something behind: {got["problems"]}')
            for account in (MANAGER, AGENT):
                want(sudo(node.name, f'id {account} >/dev/null 2>&1 && echo there; true', check=False).strip() == '', f'{account} is still an account')
            left = sudo(node.name, f'ls {CTL} /etc/sudoers.d/storageforge-agentctl /etc/storageforge-agent /var/lib/storageforge-agent 2>/dev/null; true', check=False).strip()
            want(left == '', f'still on the host: {left}')
            api('PUT', f'/api/agents/{name}', {'enabled': False})
            demo.scan(api, [node.ip])          # SSH is the base, and is as it was
            return 'stopped it stayed stopped, started it ran, removed it left nothing; a scan works as before'
        r.check('agent-stop-and-remove', node.name, stop_remove)

    for node, expect in ((with_docker, 'docker'), (with_podman, 'podman-rootless'), (bare, 'podman-rootless')):
        if node is None:
            r.add('agent-install', '-', None, f'no host for this in the build (wanted one that runs it under {expect})')
        else:
            checks_on(node, expect)

    if pve is None:
        r.add('agent-lxc-on-pve', '-', None, 'no Proxmox VE host that takes deploys in this build')
        return
    name = demo.known_as(api, pve.name)

    def on_pve():
        api('PUT', f'/api/agents/{name}', {'enabled': True})
        got = install(api, name)
        want(got['state'] == 'running', f'the agent is {got["state"]} on Proxmox VE: {got.get("detail")}')
        want(got['runtime'] == 'pct', f'it runs under {got["runtime"]}, expected pct')
        want(not has(pve, 'podman'), 'Podman was installed on a Proxmox VE host')
        vmid = sudo(pve.name, 'cat /var/lib/storageforge-agent/ctl/vmid').strip()
        conf = sudo(pve.name, f'pct config {vmid}')
        want('unprivileged: 1' in conf, 'the container is not unprivileged')
        want('nesting=1' not in conf, 'nesting is on')
        s = status_of(pve, agent_pid(pve))
        want(s['Uid'].split()[0] == sudo(pve.name, f'id -u {AGENT}').strip(), 'the agent in the container is not sfagent on the host')
        api('DELETE', f'/api/agents/{name}')
        api('PUT', f'/api/agents/{name}', {'enabled': False})
        return f'container {vmid}: unprivileged, no nesting, the process is sfagent on the host, and no Podman'
    r.check('agent-lxc-on-pve', pve.name, on_pve)
